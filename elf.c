#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <elf.h>
#include <sys/param.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define BUFSIZE 260
#define KDUMP_ELF32	(0x20)
#define KDUMP_ELF64	(0x40)

#define NR_CPUS 16

#define NT_TASKSTRUCT 4

#define ELFSTORE 1
#define ELFREAD	 0

#define PRSTATUS_NOTE (1)

#define netdump_print printf

struct arm64_elf_siginfo {
	int si_signo;
	int si_code;
	int si_errno;
};

struct arm64_elf_prstatus {
	struct arm64_elf_siginfo pr_info;
	short pr_cursig;
	unsigned long pr_sigpend;
	unsigned long pr_sighold;
	pid_t pr_pid;
	pid_t pr_ppid;
	pid_t pr_pgrp;
	pid_t pr_sid;
	struct timeval pr_utime;
	struct timeval pr_stime;
	struct timeval pr_cutime;
	struct timeval pr_cstime;
/*  arm64_elf_gregset_t pr_reg; -> typedef unsigned long [34] arm64_elf_gregset_t */
	unsigned long pr_reg[34];
	int pr_fpvalid;
};

struct pt_load_segment {
	off_t file_offset;
	ulong phys_start;
	ulong phys_end;
	ulong zero_fill;
};

struct vmcore_data {
	ulong flags;
	int ndfd;
	FILE *ofp;
	uint header_size;
	char *elf_header;
	uint num_pt_load_segments;
	struct pt_load_segment *pt_load_segments;
	Elf32_Ehdr *elf32;
	Elf32_Phdr *notes32;
	Elf32_Phdr *load32;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *notes64;
	Elf64_Phdr *load64;
	Elf64_Shdr *sect0_64;
	void *nt_prstatus;
	void *nt_prpsinfo;
	void *nt_taskstruct;
	ulong task_struct;
	uint page_size;
	ulong switch_stack;
	uint num_prstatus_notes;
	void *nt_prstatus_percpu[NR_CPUS];
	void *vmcoreinfo;
	uint size_vmcoreinfo;
/* Backup Region, first 640K of System RAM. */
#define KEXEC_BACKUP_SRC_END	0x0009ffff
	uint num_qemu_notes;
	void *nt_qemu_percpu[NR_CPUS];
	ulong backup_src_start;
	ulong backup_src_size;
	ulong backup_offset;
	ulong arch_data;
#define arch_data1 arch_data
	ulong phys_base;
	ulong arch_data2;
	//void *nt_vmcoredd_array[NR_DEVICE_DUMPS];
	uint num_vmcoredd_notes;
};

static struct vmcore_data vmcore_data;
static struct vmcore_data *nd = &vmcore_data;

static int core_fd;

static int vmcore_init(char *file)
{
	int i, fd;
	Elf32_Ehdr *elf32;
	Elf32_Phdr *load32;
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	char eheader[BUFSIZE];
	size_t header_size, tot;
	Elf32_Off p_offset32;
	Elf64_Off p_offset64;
	ulong format;
	uint num_pt_load_segments;

	core_fd = open(file, O_RDONLY);
	if (core_fd < 0) {
		perror("open");
		return -1;
	}

	if ((fd = open(file, O_RDONLY)) < 0) {
		perror("open");
		return -1;
	}
	if (read(fd, eheader, BUFSIZE) != BUFSIZE) {
		perror("read");
		close(fd);
		return -1;
	}
	close(fd);

	elf32 = (Elf32_Ehdr *) & eheader[0];
	elf64 = (Elf64_Ehdr *) & eheader[0];

	if (elf32->e_ident[EI_CLASS] == ELFCLASS32)
		format = KDUMP_ELF32;
	else if (elf64->e_ident[EI_CLASS] == ELFCLASS64)
		format = KDUMP_ELF64;
	else {
		fprintf(stderr, "Invalid ELF class\n");
		return -1;
	}

	switch (format) {
	case KDUMP_ELF32:
		num_pt_load_segments = elf32->e_phnum - 1;
		header_size = MAX(sizeof(Elf32_Ehdr), elf32->e_phoff) +
		    (sizeof(Elf32_Phdr) * (num_pt_load_segments + 1));
		break;

	case KDUMP_ELF64:
		num_pt_load_segments = elf64->e_phnum - 1;

		header_size = MAX(sizeof(Elf64_Ehdr), elf64->e_phoff) +
		    (sizeof(Elf64_Phdr) * (num_pt_load_segments + 1));
		break;
	}

	nd->flags = format;
	nd->elf_header = malloc(header_size);
	if (!nd->elf_header) {
		fprintf(stderr, "Error in malloc\n");
		return -1;
	}

	if ((fd = open(file, O_RDONLY)) < 0) {
		perror("open");
		return -1;
	}
	if (read(fd, nd->elf_header, header_size) != header_size) {
		perror("read");
		close(fd);
		return -1;
	}
	close(fd);

	switch (format) {
	case KDUMP_ELF32:
		load32 =
		    (Elf32_Phdr *) & eheader[elf32->e_phoff +
					     sizeof(Elf32_Phdr)];
		p_offset32 = load32->p_offset;
		for (i = 0; i < num_pt_load_segments; i++, load32 += 1) {
			if (load32->p_offset && (p_offset32 > load32->p_offset))
				p_offset32 = load32->p_offset;
		}
		header_size = (size_t)p_offset32;
		break;

	case KDUMP_ELF64:
		load64 =
		    (Elf64_Phdr *) & eheader[elf64->e_phoff +
					     sizeof(Elf64_Phdr)];
		p_offset64 = load64->p_offset;
		for (i = 0; i < num_pt_load_segments; i++, load64 += 1) {
			if (load64->p_offset && (p_offset64 > load64->p_offset))
				p_offset64 = load64->p_offset;
		}
		header_size = (size_t)p_offset64;
		break;
	}

	nd->elf_header = realloc(nd->elf_header, header_size);
	if (!nd->elf_header) {
		fprintf(stderr, "realloc failed!\n");
		return -1;
	}

	nd->header_size = header_size;

	if ((fd = open(file, O_RDONLY)) < 0) {
		perror("open");
		return -1;
	}
	if (read(fd, nd->elf_header, header_size) != header_size) {
		perror("read");
		close(fd);
		return -1;
	}
	close(fd);

	switch (format) {
	case KDUMP_ELF32:
		nd->elf32 = (Elf32_Ehdr *) & nd->elf_header[0];
		nd->num_pt_load_segments = nd->elf32->e_phnum - 1;

		nd->pt_load_segments =
		    malloc(sizeof(struct pt_load_segment) *
			   nd->num_pt_load_segments);
		if (!nd->pt_load_segments) {
			fprintf(stderr,
				"cannot malloc PT_LOAD segment buffers\n");
			free(nd->elf_header);
			return -1;
		}
		nd->notes32 = (Elf32_Phdr *)
		    & nd->elf_header[nd->elf32->e_phoff];
		nd->load32 = nd->notes32 + 1;

		break;

	case KDUMP_ELF64:
		nd->elf64 = (Elf64_Ehdr *) & nd->elf_header[0];
		nd->num_pt_load_segments = nd->elf64->e_phnum - 1;

		nd->pt_load_segments =
		    malloc(sizeof(struct pt_load_segment) *
			   nd->num_pt_load_segments);
		if (!nd->pt_load_segments) {
			fprintf(stderr,
				"cannot malloc PT_LOAD segment buffers\n");
			free(nd->elf_header);
		}
		nd->notes64 = (Elf64_Phdr *)
		    & nd->elf_header[nd->elf64->e_phoff];
		nd->load64 = nd->notes64 + 1;

		break;
	}
}

static void vmcore_deinit(void)
{
	free(nd->elf_header);
	free(nd->pt_load_segments);
	close(core_fd);
}

static void dump_Elf32_Ehdr(Elf32_Ehdr * elf)
{
	char buf[BUFSIZE];

	bzero(buf, BUFSIZE);
	bcopy(elf->e_ident, buf, SELFMAG);
	printf("Elf32_Ehdr:\n");
	printf("                e_ident: \\%o%s\n", buf[0], &buf[1]);
	printf("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS]) {
	case ELFCLASSNONE:
		printf("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		printf("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		printf("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		printf("(ELFCLASSNUM)\n");
		break;
	default:
		printf("(?)\n");
		break;
	}
	printf("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA]) {
	case ELFDATANONE:
		printf("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB:
		printf("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		printf("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		printf("(ELFDATANUM)\n");
		break;
	default:
		printf("(?)\n");
	}
	printf("    e_ident[EI_VERSION]: %d ", elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		printf("(EV_CURRENT)\n");
	else
		printf("(?)\n");
	printf("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI]) {
	case ELFOSABI_SYSV:
		printf("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:
		printf("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:
		printf("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		printf("(ELFOSABI_STANDALONE)\n");
		break;
	case ELFOSABI_LINUX:
		printf("(ELFOSABI_LINUX)\n");
		break;
	default:
		printf("(?)\n");
	}
	printf(" e_ident[EI_ABIVERSION]: %d\n", elf->e_ident[EI_ABIVERSION]);

	printf("                 e_type: %d ", elf->e_type);
	switch (elf->e_type) {
	case ET_NONE:
		printf("(ET_NONE)\n");
		break;
	case ET_REL:
		printf("(ET_REL)\n");
		break;
	case ET_EXEC:
		printf("(ET_EXEC)\n");
		break;
	case ET_DYN:
		printf("(ET_DYN)\n");
		break;
	case ET_CORE:
		printf("(ET_CORE)\n");
		break;
	case ET_NUM:
		printf("(ET_NUM)\n");
		break;
	case ET_LOOS:
		printf("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		printf("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		printf("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		printf("(ET_HIPROC)\n");
		break;
	default:
		printf("(?)\n");
	}

	printf("              e_machine: %d ", elf->e_machine);
	switch (elf->e_machine) {
	case EM_ARM:
		printf("(EM_ARM)\n");
		break;
	case EM_386:
		printf("(EM_386)\n");
		break;
	case EM_MIPS:
		printf("(EM_MIPS)\n");
		break;
	default:
		printf("(unsupported)\n");
		break;
	}

	printf("              e_version: %ld ", elf->e_version);
	printf("%s\n", elf->e_version == EV_CURRENT ? "(EV_CURRENT)" : "");

	printf("                e_entry: %lx\n", elf->e_entry);
	printf("                e_phoff: %lx\n", elf->e_phoff);
	printf("                e_shoff: %lx\n", elf->e_shoff);
	printf("                e_flags: %lx\n", elf->e_flags);

	printf("               e_ehsize: %x\n", elf->e_ehsize);
	printf("            e_phentsize: %x\n", elf->e_phentsize);
	printf("                e_phnum: %x\n", elf->e_phnum);
	printf("            e_shentsize: %x\n", elf->e_shentsize);
	printf("                e_shnum: %x\n", elf->e_shnum);
	printf("             e_shstrndx: %x\n", elf->e_shstrndx);
}

static void dump_Elf64_Ehdr(Elf64_Ehdr * elf)
{
	char buf[BUFSIZE];

	bzero(buf, BUFSIZE);
	bcopy(elf->e_ident, buf, SELFMAG);
	printf("Elf64_Ehdr:\n");
	printf("                e_ident: \\%o%s\n", buf[0], &buf[1]);
	printf("      e_ident[EI_CLASS]: %d ", elf->e_ident[EI_CLASS]);
	switch (elf->e_ident[EI_CLASS]) {
	case ELFCLASSNONE:
		printf("(ELFCLASSNONE)");
		break;
	case ELFCLASS32:
		printf("(ELFCLASS32)\n");
		break;
	case ELFCLASS64:
		printf("(ELFCLASS64)\n");
		break;
	case ELFCLASSNUM:
		printf("(ELFCLASSNUM)\n");
		break;
	default:
		printf("(?)\n");
		break;
	}
	printf("       e_ident[EI_DATA]: %d ", elf->e_ident[EI_DATA]);
	switch (elf->e_ident[EI_DATA]) {
	case ELFDATANONE:
		printf("(ELFDATANONE)\n");
		break;
	case ELFDATA2LSB:
		printf("(ELFDATA2LSB)\n");
		break;
	case ELFDATA2MSB:
		printf("(ELFDATA2MSB)\n");
		break;
	case ELFDATANUM:
		printf("(ELFDATANUM)\n");
		break;
	default:
		printf("(?)\n");
	}
	printf("    e_ident[EI_VERSION]: %d ", elf->e_ident[EI_VERSION]);
	if (elf->e_ident[EI_VERSION] == EV_CURRENT)
		printf("(EV_CURRENT)\n");
	else
		printf("(?)\n");
	printf("      e_ident[EI_OSABI]: %d ", elf->e_ident[EI_OSABI]);
	switch (elf->e_ident[EI_OSABI]) {
	case ELFOSABI_SYSV:
		printf("(ELFOSABI_SYSV)\n");
		break;
	case ELFOSABI_HPUX:
		printf("(ELFOSABI_HPUX)\n");
		break;
	case ELFOSABI_ARM:
		printf("(ELFOSABI_ARM)\n");
		break;
	case ELFOSABI_STANDALONE:
		printf("(ELFOSABI_STANDALONE)\n");
		break;
	case ELFOSABI_LINUX:
		printf("(ELFOSABI_LINUX)\n");
		break;
	default:
		printf("(?)\n");
	}
	printf(" e_ident[EI_ABIVERSION]: %d\n", elf->e_ident[EI_ABIVERSION]);

	printf("                 e_type: %d ", elf->e_type);
	switch (elf->e_type) {
	case ET_NONE:
		printf("(ET_NONE)\n");
		break;
	case ET_REL:
		printf("(ET_REL)\n");
		break;
	case ET_EXEC:
		printf("(ET_EXEC)\n");
		break;
	case ET_DYN:
		printf("(ET_DYN)\n");
		break;
	case ET_CORE:
		printf("(ET_CORE)\n");
		break;
	case ET_NUM:
		printf("(ET_NUM)\n");
		break;
	case ET_LOOS:
		printf("(ET_LOOS)\n");
		break;
	case ET_HIOS:
		printf("(ET_HIOS)\n");
		break;
	case ET_LOPROC:
		printf("(ET_LOPROC)\n");
		break;
	case ET_HIPROC:
		printf("(ET_HIPROC)\n");
		break;
	default:
		printf("(?)\n");
	}

	printf("              e_machine: %d ", elf->e_machine);
	switch (elf->e_machine) {
	case EM_386:
		printf("(EM_386)\n");
		break;
	case EM_IA_64:
		printf("(EM_IA_64)\n");
		break;
	case EM_PPC64:
		printf("(EM_PPC64)\n");
		break;
	case EM_X86_64:
		printf("(EM_X86_64)\n");
		break;
	case EM_S390:
		printf("(EM_S390)\n");
		break;
	case EM_ARM:
		printf("(EM_ARM)\n");
		break;
	case EM_AARCH64:
		printf("(EM_AARCH64)\n");
		break;
	default:
		printf("(unsupported)\n");
		break;
	}

	printf("              e_version: %ld ", elf->e_version);
	printf("%s\n", elf->e_version == EV_CURRENT ? "(EV_CURRENT)" : "");

	printf("                e_entry: %lx\n", elf->e_entry);
	printf("                e_phoff: %lx\n", elf->e_phoff);
	printf("                e_shoff: %lx\n", elf->e_shoff);
	printf("                e_flags: %lx\n", elf->e_flags);

	printf("               e_ehsize: %x\n", elf->e_ehsize);
	printf("            e_phentsize: %x\n", elf->e_phentsize);
	printf("                e_phnum: %x\n", elf->e_phnum);
	printf("            e_shentsize: %x\n", elf->e_shentsize);
	printf("                e_shnum: %x\n", elf->e_shnum);
	printf("             e_shstrndx: %x\n", elf->e_shstrndx);
}

static void dump_Elf32_Phdr(Elf32_Phdr * prog, int store_pt_load_data)
{
	int others;
	struct pt_load_segment *pls;

	if ((char *)prog > (nd->elf_header + nd->header_size))
		fprintf(stderr,
			"Elf32_Phdr pointer: %lx  ELF header end: %lx\n\n",
			(char *)prog, nd->elf_header + nd->header_size);

	if (store_pt_load_data)
		pls = &nd->pt_load_segments[store_pt_load_data - 1];
	else
		pls = NULL;

	printf("Elf32_Phdr:\n");
	printf("                 p_type: %lx ", prog->p_type);
	switch (prog->p_type) {
	case PT_NULL:
		printf("(PT_NULL)\n");
		break;
	case PT_LOAD:
		printf("(PT_LOAD)\n");
		break;
	case PT_DYNAMIC:
		printf("(PT_DYNAMIC)\n");
		break;
	case PT_INTERP:
		printf("(PT_INTERP)\n");
		break;
	case PT_NOTE:
		printf("(PT_NOTE)\n");
		break;
	case PT_SHLIB:
		printf("(PT_SHLIB)\n");
		break;
	case PT_PHDR:
		printf("(PT_PHDR)\n");
		break;
	case PT_NUM:
		printf("(PT_NUM)\n");
		break;
	case PT_LOOS:
		printf("(PT_LOOS)\n");
		break;
	case PT_HIOS:
		printf("(PT_HIOS)\n");
		break;
	case PT_LOPROC:
		printf("(PT_LOPROC)\n");
		break;
	case PT_HIPROC:
		printf("(PT_HIPROC)\n");
		break;
	default:
		printf("(?)\n");
	}

	printf("               p_offset: %ld (%lx)\n", prog->p_offset,
	       prog->p_offset);
	if (store_pt_load_data)
		pls->file_offset = prog->p_offset;
	printf("                p_vaddr: %lx\n", prog->p_vaddr);
	printf("                p_paddr: %lx\n", prog->p_paddr);
	if (store_pt_load_data)
		pls->phys_start = prog->p_paddr;
	printf("               p_filesz: %lu (%lx)\n", prog->p_filesz,
	       prog->p_filesz);
	if (store_pt_load_data) {
		pls->phys_end = pls->phys_start + prog->p_filesz;
		pls->zero_fill = (prog->p_filesz == prog->p_memsz) ?
		    0 : pls->phys_start + prog->p_memsz;
	}
	printf("                p_memsz: %lu (%lx)\n", prog->p_memsz,
	       prog->p_memsz);
	printf("                p_flags: %lx (", prog->p_flags);
	others = 0;
	if (prog->p_flags & PF_X)
		printf("PF_X", others++);
	if (prog->p_flags & PF_W)
		printf("%sPF_W", others++ ? "|" : "");
	if (prog->p_flags & PF_R)
		printf("%sPF_R", others++ ? "|" : "");
	printf(")\n");
	printf("                p_align: %ld\n", prog->p_align);
}

static void dump_Elf64_Phdr(Elf64_Phdr * prog, int store_pt_load_data)
{
	int others;
	struct pt_load_segment *pls;

	if (store_pt_load_data)
		pls = &nd->pt_load_segments[store_pt_load_data - 1];
	else
		pls = NULL;

	if ((char *)prog > (nd->elf_header + nd->header_size))
		fprintf(stderr,
			"Elf64_Phdr pointer: %lx  ELF header end: %lx\n\n",
			(char *)prog, nd->elf_header + nd->header_size);

	printf("Elf64_Phdr:\n");
	printf("                 p_type: %lx ", prog->p_type);
	switch (prog->p_type) {
	case PT_NULL:
		printf("(PT_NULL)\n");
		break;
	case PT_LOAD:
		printf("(PT_LOAD)\n");
		break;
	case PT_DYNAMIC:
		printf("(PT_DYNAMIC)\n");
		break;
	case PT_INTERP:
		printf("(PT_INTERP)\n");
		break;
	case PT_NOTE:
		printf("(PT_NOTE)\n");
		break;
	case PT_SHLIB:
		printf("(PT_SHLIB)\n");
		break;
	case PT_PHDR:
		printf("(PT_PHDR)\n");
		break;
	case PT_NUM:
		printf("(PT_NUM)\n");
		break;
	case PT_LOOS:
		printf("(PT_LOOS)\n");
		break;
	case PT_HIOS:
		printf("(PT_HIOS)\n");
		break;
	case PT_LOPROC:
		printf("(PT_LOPROC)\n");
		break;
	case PT_HIPROC:
		printf("(PT_HIPROC)\n");
		break;
	default:
		printf("(?)\n");
	}

	printf("               p_offset: %lld (%llx)\n", prog->p_offset,
	       prog->p_offset);
	if (store_pt_load_data)
		pls->file_offset = prog->p_offset;
	printf("                p_vaddr: %llx\n", prog->p_vaddr);
	printf("                p_paddr: %llx\n", prog->p_paddr);
	if (store_pt_load_data)
		pls->phys_start = prog->p_paddr;
	printf("               p_filesz: %llu (%llx)\n", prog->p_filesz,
	       prog->p_filesz);
	if (store_pt_load_data) {
		pls->phys_end = pls->phys_start + prog->p_filesz;
		pls->zero_fill = (prog->p_filesz == prog->p_memsz) ?
		    0 : pls->phys_start + prog->p_memsz;
	}
	printf("                p_memsz: %llu (%llx)\n", prog->p_memsz,
	       prog->p_memsz);
	printf("                p_flags: %lx (", prog->p_flags);
	others = 0;
	if (prog->p_flags & PF_X)
		printf("PF_X", others++);
	if (prog->p_flags & PF_W)
		printf("%sPF_W", others++ ? "|" : "");
	if (prog->p_flags & PF_R)
		printf("%sPF_R", others++ ? "|" : "");
	printf(")\n");
	printf("                p_align: %lld\n", prog->p_align);
}

static size_t dump_Elf32_Nhdr(Elf32_Off offset, int store)
{
	int i, lf;
	Elf32_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	uint *uptr;
	int xen_core, vmcoreinfo, vmcoreinfo_xen, eraseinfo, qemuinfo;
	uint64_t remaining, notesize;

	note = (Elf32_Nhdr *) ((char *)nd->elf32 + offset);

	bzero(buf, BUFSIZE);
	xen_core = vmcoreinfo = eraseinfo = qemuinfo = 0;
	ptr = (char *)note + sizeof(Elf32_Nhdr);

	if (ptr > (nd->elf_header + nd->header_size)) {
		fprintf(stderr,
			"Elf32_Nhdr pointer: %lx ELF header end: %lx\n",
			(char *)note, nd->elf_header + nd->header_size);
		return 0;
	} else
		remaining =
		    (uint64_t) ((nd->elf_header + nd->header_size) - ptr);

	notesize = (uint64_t) note->n_namesz + (uint64_t) note->n_descsz;

	if ((note->n_namesz == 0) || !remaining || (notesize > remaining)) {
		fprintf(stderr,
			"possibly corrupt Elf32_Nhdr: "
			"n_namesz: %ld n_descsz: %ld n_type: %lx\n%s",
			note->n_namesz, note->n_descsz, note->n_type,
			note->n_namesz || note->n_descsz || !remaining ?
			"\n" : "");
		if (note->n_namesz || note->n_descsz || !remaining)
			return 0;
	}

	printf("Elf32_Nhdr:\n");
	printf("               n_namesz: %ld ", note->n_namesz);

	bcopy(ptr, buf, note->n_namesz);
	printf("(\"%s\")\n", buf);

	printf("               n_descsz: %ld\n", note->n_descsz);
	printf("                 n_type: %lx ", note->n_type);
	switch (note->n_type) {
	case NT_PRSTATUS:
		printf("(NT_PRSTATUS)\n");
		if (store) {
			if (!nd->nt_prstatus)
				nd->nt_prstatus = (void *)note;
			for (i = 0; i < NR_CPUS; i++) {
				if (!nd->nt_prstatus_percpu[i]) {
					nd->nt_prstatus_percpu[i] =
					    (void *)note;
					nd->num_prstatus_notes++;
					break;
				}
			}
		}
		break;
	case NT_PRPSINFO:
		printf("(NT_PRPSINFO)\n");
		if (store)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_TASKSTRUCT:
		printf("(NT_TASKSTRUCT)\n");
		if (store) {
			nd->nt_taskstruct = (void *)note;
			nd->task_struct = *((ulong *) (ptr + note->n_namesz));
		}
		break;
	default:
		vmcoreinfo = !strncmp(buf, "VMCOREINFO", 10);
		if (vmcoreinfo) {
			printf("(unused)\n");
			nd->vmcoreinfo = (char *)(ptr + note->n_namesz + 1);
			nd->size_vmcoreinfo = note->n_descsz;
		} else
			printf("(?)\n");
		break;
	}

	uptr = (uint *) (ptr + note->n_namesz);

	/*
	 * kdumps are off-by-1, because their n_namesz is 5 for "CORE".
	 */
	if ((nd->flags & KDUMP_ELF32) && (note->n_namesz == 5))
		uptr = (uint *) (ptr + ((note->n_namesz + 3) & ~3));

	if (vmcoreinfo) {
		printf("                         ");
		ptr += note->n_namesz + 1;
		for (i = 0; i < note->n_descsz; i++, ptr++) {
			printf("%c", *ptr);
			if (*ptr == '\n')
				printf("                         ");
		}
		lf = 0;
	} else {
		for (i = lf = 0; i < note->n_descsz / sizeof(uint); i++) {
			if (((i % 4) == 0)) {
				printf("%s                         ",
				       i ? "\n" : "");
				lf++;
			} else
				lf = 0;
			printf("%08lx ", *uptr++);
		}
	}

	printf("\n");

	len = sizeof(Elf32_Nhdr);
	len = roundup(len + note->n_namesz, 4);
	len = roundup(len + note->n_descsz, 4);

	return len;
}

char *space(int cnt)
{
#define SPACES 40
#define MINSPACE  (-100)
#define VADDR_PRLEN      (sizeof(char *) == 8 ? 16 : 8)
	static char spacebuf[SPACES + 1] = { 0 };
	int i;
	char *bigspace;

	if (!strlen(spacebuf)) {
		for (i = 0; i < SPACES; i++)
			spacebuf[i] = ' ';
		spacebuf[i] = '\0';
	}

	if (cnt < (MINSPACE - 1))
		fprintf(stderr, "illegal spacing request: %d\n", cnt);
	if ((cnt > MINSPACE + 1) && (cnt < 0))
		fprintf(stderr, "illegal spacing request\n");

	switch (cnt) {
	case (MINSPACE - 1):
		if (VADDR_PRLEN > 8)
			return (&spacebuf[SPACES]);	/* NULL */
		else
			return (&spacebuf[SPACES - 1]);	/* 1 space */

	case MINSPACE:
		if (VADDR_PRLEN > 8)
			return (&spacebuf[SPACES - 1]);	/* 1 space */
		else
			return (&spacebuf[SPACES - 2]);	/* 2 spaces */

	case (MINSPACE + 1):
		if (VADDR_PRLEN > 8)
			return (&spacebuf[SPACES - 2]);	/* 2 spaces */
		else
			return (&spacebuf[SPACES - 3]);	/* 3 spaces */

	default:
		return (&spacebuf[SPACES - cnt]);	/* as requested */
	}
}

static void display_prstatus_arm64(void *note_ptr, FILE * ofp)
{
	struct arm64_elf_prstatus *pr;
	Elf64_Nhdr *note;
	int sp;

	note = (Elf64_Nhdr *) note_ptr;
	pr = (struct arm64_elf_prstatus *)((char *)note + sizeof(Elf64_Nhdr) +
					   note->n_namesz);
	pr = (struct arm64_elf_prstatus *)roundup((ulong) pr, 4);
	sp = nd->num_prstatus_notes ? 25 : 22;

	fprintf(ofp,
		"%ssi.signo: %d  si.code: %d  si.errno: %d\n"
		"%scursig: %d  sigpend: %lx  sighold: %lx\n"
		"%spid: %d  ppid: %d  pgrp: %d  sid:%d\n"
		"%sutime: %01lld.%06d  stime: %01lld.%06d\n"
		"%scutime: %01lld.%06d  cstime: %01lld.%06d\n",
		space(sp), pr->pr_info.si_signo, pr->pr_info.si_code,
		pr->pr_info.si_errno, space(sp), pr->pr_cursig, pr->pr_sigpend,
		pr->pr_sighold, space(sp), pr->pr_pid, pr->pr_ppid, pr->pr_pgrp,
		pr->pr_sid, space(sp), (long long)pr->pr_utime.tv_sec,
		(int)pr->pr_utime.tv_usec, (long long)pr->pr_stime.tv_sec,
		(int)pr->pr_stime.tv_usec, space(sp),
		(long long)pr->pr_cutime.tv_sec, (int)pr->pr_cutime.tv_usec,
		(long long)pr->pr_cstime.tv_sec, (int)pr->pr_cstime.tv_usec);
	fprintf(ofp,
		"%s X0: %016lx   X1: %016lx   X2: %016lx\n"
		"%s X3: %016lx   X4: %016lx   X5: %016lx\n"
		"%s X6: %016lx   X7: %016lx   X8: %016lx\n"
		"%s X9: %016lx  X10: %016lx  X11: %016lx\n"
		"%sX12: %016lx  X13: %016lx  X14: %016lx\n"
		"%sX15: %016lx  X16: %016lx  X17: %016lx\n"
		"%sX18: %016lx  X19: %016lx  X20: %016lx\n"
		"%sX21: %016lx  X22: %016lx  X23: %016lx\n"
		"%sX24: %016lx  X25: %016lx  X26: %016lx\n"
		"%sX27: %016lx  X28: %016lx  X29: %016lx\n"
		"%s LR: %016lx   SP: %016lx   PC: %016lx\n"
		"%sPSTATE: %08lx   FPVALID: %08x\n", space(sp), pr->pr_reg[0],
		pr->pr_reg[1], pr->pr_reg[2], space(sp), pr->pr_reg[3],
		pr->pr_reg[4], pr->pr_reg[5], space(sp), pr->pr_reg[6],
		pr->pr_reg[7], pr->pr_reg[8], space(sp), pr->pr_reg[9],
		pr->pr_reg[10], pr->pr_reg[11], space(sp), pr->pr_reg[12],
		pr->pr_reg[13], pr->pr_reg[14], space(sp), pr->pr_reg[15],
		pr->pr_reg[16], pr->pr_reg[17], space(sp), pr->pr_reg[18],
		pr->pr_reg[19], pr->pr_reg[20], space(sp), pr->pr_reg[21],
		pr->pr_reg[22], pr->pr_reg[23], space(sp), pr->pr_reg[24],
		pr->pr_reg[25], pr->pr_reg[26], space(sp), pr->pr_reg[27],
		pr->pr_reg[28], pr->pr_reg[29], space(sp), pr->pr_reg[30],
		pr->pr_reg[31], pr->pr_reg[32], space(sp), pr->pr_reg[33],
		pr->pr_fpvalid);
}

void display_ELF_note(int machine, int type, void *note, FILE * ofp)
{
	if (note == NULL)
		return;

	switch (machine) {
	case EM_AARCH64:
		switch (type) {
		case PRSTATUS_NOTE:
			display_prstatus_arm64(note, ofp);
			break;
		}
		break;
	}
}

static size_t dump_Elf64_Nhdr(Elf64_Off offset, int store)
{
	int i = 0, lf = 0;
	Elf64_Nhdr *note;
	size_t len;
	char buf[BUFSIZE];
	char *ptr;
	ulong *uptr;
	int *iptr;
	int xen_core, vmcoreinfo, vmcoreinfo_xen, eraseinfo, qemuinfo;
	uint64_t remaining, notesize;

	note = (Elf64_Nhdr *) ((char *)nd->elf64 + offset);

	bzero(buf, BUFSIZE);
	ptr = (char *)note + sizeof(Elf64_Nhdr);
	xen_core = vmcoreinfo = vmcoreinfo_xen = eraseinfo = qemuinfo = 0;

	if (ptr > (nd->elf_header + nd->header_size)) {
		fprintf(stderr,
			"Elf64_Nhdr pointer: %lx  ELF header end: %lx\n\n",
			(char *)note, nd->elf_header + nd->header_size);
		return 0;
	} else
		remaining =
		    (uint64_t) ((nd->elf_header + nd->header_size) - ptr);

	notesize = (uint64_t) note->n_namesz + (uint64_t) note->n_descsz;

	if ((note->n_namesz == 0) || !remaining || (notesize > remaining)) {
		fprintf(stderr,
			"possibly corrupt Elf64_Nhdr: "
			"n_namesz: %ld n_descsz: %ld n_type: %lx\n%s",
			note->n_namesz, note->n_descsz, note->n_type,
			note->n_namesz || note->n_descsz || !remaining ?
			"\n" : "");
		if (note->n_namesz || note->n_descsz || !remaining)
			return 0;
	}

	printf("Elf64_Nhdr:\n");
	printf("               n_namesz: %ld ", note->n_namesz);

	bcopy(ptr, buf, note->n_namesz);
	printf("(\"%s\")\n", buf);

	printf("               n_descsz: %ld\n", note->n_descsz);
	printf("                 n_type: %lx ", note->n_type);
	switch (note->n_type) {
	case NT_PRSTATUS:
		printf("(NT_PRSTATUS)\n");
		if (store) {
			if (!nd->nt_prstatus)
				nd->nt_prstatus = (void *)note;
			for (i = 0; i < NR_CPUS; i++) {
				if (!nd->nt_prstatus_percpu[i]) {
					nd->nt_prstatus_percpu[i] =
					    (void *)note;
					nd->num_prstatus_notes++;
					break;
				}
			}
		}
		break;
	case NT_PRPSINFO:
		printf("(NT_PRPSINFO)\n");
		if (store)
			nd->nt_prpsinfo = (void *)note;
		break;
	case NT_FPREGSET:
		printf("(NT_FPREGSET)\n");
		break;
	case NT_S390_TIMER:
		printf("(NT_S390_TIMER)\n");
		break;
	case NT_S390_TODCMP:
		printf("(NT_S390_TODCMP)\n");
		break;
	case NT_S390_TODPREG:
		printf("(NT_S390_TODPREG)\n");
		break;
	case NT_S390_CTRS:
		printf("(NT_S390_CTRS)\n");
		break;
	case NT_S390_PREFIX:
		printf("(NT_S390_PREFIX)\n");
		break;
	case NT_S390_VXRS_LOW:
		printf("(NT_S390_VXRS_LOW)\n");
		break;
	case NT_S390_VXRS_HIGH:
		printf("(NT_S390_VXRS_HIGH)\n");
		break;
	default:
		vmcoreinfo = !strncmp(buf, "VMCOREINFO", 10);
		if (vmcoreinfo) {
			printf("(unused)\n");
			nd->vmcoreinfo = (char *)nd->elf64 + offset +
			    (sizeof(Elf64_Nhdr) + ((note->n_namesz + 3) & ~3));
			nd->size_vmcoreinfo = note->n_descsz;
		} else
			printf("(?)\n");
		break;
	}

	uptr = (ulong *) (ptr + note->n_namesz);

	/*
	 * kdumps are off-by-1, because their n_namesz is 5 for "CORE".
	 */
	if ((nd->flags & KDUMP_ELF64) && (note->n_namesz == 5))
		uptr = (ulong *) (ptr + ((note->n_namesz + 3) & ~3));

	if (store && qemuinfo) {
		for (i = 0; i < NR_CPUS; i++) {
			if (!nd->nt_qemu_percpu[i]) {
				nd->nt_qemu_percpu[i] = (void *)uptr;
				nd->num_qemu_notes++;
				break;
			}
		}
	}

	if (vmcoreinfo) {
		printf("                         ");
		ptr += note->n_namesz + 1;
		for (i = 0; i < note->n_descsz; i++, ptr++) {
			printf("%c", *ptr);
			if (*ptr == '\n')
				printf("                         ");
		}
		lf = 0;
	} else if (note->n_descsz == 4) {
		i = 0;
		lf = 1;
		iptr = (int *)uptr;
		printf("                         %08lx\n", *iptr);
	} else {
		if (note->n_type == NT_PRSTATUS)
			display_ELF_note(EM_AARCH64, PRSTATUS_NOTE, note,
					 stdout);
		for (i = lf = 0; i < note->n_descsz / sizeof(ulong); i++) {
			if (((i % 2) == 0)) {
				printf("%s                         ",
				       i ? "\n" : "");
				lf++;
			} else
				lf = 0;
			printf("%016llx ", *uptr++);
		}
	}
	if (!lf)
		printf("\n");
	else if (i && (i & 1))
		printf("\n");

	len = sizeof(Elf64_Nhdr);
	len = roundup(len + note->n_namesz, 4);
	len = roundup(len + note->n_descsz, 4);

	return len;
}

static void dump_vmcore_info(void)
{
	int i;
	Elf32_Off offset32;
	Elf64_Off offset64;
	size_t len, tot;

	if (nd->flags == KDUMP_ELF32) {
		dump_Elf32_Ehdr(nd->elf32);
		dump_Elf32_Phdr(nd->notes32, ELFREAD);

		for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf32_Phdr(nd->load32 + i, ELFSTORE + i);

		offset32 = nd->notes32->p_offset;
		for (tot = 0; tot < nd->notes32->p_filesz; tot += len) {
			if (!(len = dump_Elf32_Nhdr(offset32, ELFSTORE)))
				break;
			offset32 += len;
		}
	} else if (nd->flags == KDUMP_ELF64) {
		dump_Elf64_Ehdr(nd->elf64);
		dump_Elf64_Phdr(nd->notes64, ELFREAD);

		for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf64_Phdr(nd->load64 + i, ELFSTORE + i);

		offset64 = nd->notes64->p_offset;
		for (tot = 0; tot < nd->notes64->p_filesz; tot += len) {
			if (!(len = dump_Elf64_Nhdr(offset64, ELFSTORE)))
				break;
			offset64 += len;
		}
	}

}

static void dump_header_info(void)
{
	int i;

	if (nd->flags == KDUMP_ELF32) {
		dump_Elf32_Ehdr(nd->elf32);
		dump_Elf32_Phdr(nd->notes32, ELFREAD);

		for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf32_Phdr(nd->load32 + i, ELFSTORE + i);
	} else if (nd->flags == KDUMP_ELF64) {
		dump_Elf64_Ehdr(nd->elf64);
		dump_Elf64_Phdr(nd->notes64, ELFREAD);

		for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf64_Phdr(nd->load64 + i, ELFSTORE + i);
	}
}

static int is_in_phdr32(Elf32_Phdr * load32, u32 addr)
{
	return addr >= load32->p_vaddr
	    && addr < load32->p_vaddr + load32->p_filesz;
}

static int is_in_phdr64(Elf64_Phdr * load64, ulong addr)
{
	return addr >= load64->p_vaddr
	    && addr < load64->p_vaddr + load64->p_filesz;
}

static int is_in_phdr(void *load, ulong addr)
{
	if (nd->flags == KDUMP_ELF32)
		return is_in_phdr32(load, addr & 0xffffffff);
	else if (nd->flags == KDUMP_ELF64)
		return is_in_phdr64(load, addr);

	return -1;
}

static void cmd_rd(ulong addr)
{
	int i;
	Elf32_Phdr *load32;
	Elf64_Phdr *load64;
	off_t offset;
	ulong val;

	if (nd->flags == KDUMP_ELF32) {
		for (i = 0; i < nd->num_pt_load_segments; i++) {
			load32 = nd->load32 + i;
			if (!is_in_phdr32(load32, addr))
				continue;
			break;
		}
	} else if (nd->flags == KDUMP_ELF64) {
		for (i = 0; i < nd->num_pt_load_segments; i++) {
			load64 = nd->load64 + i;
			if (!is_in_phdr64(load64, addr))
				continue;
			break;
		}
	}

	if (i == nd->num_pt_load_segments) {
		fprintf(stderr, "Not in range\n");
		return;
	}

	if (nd->flags == KDUMP_ELF32) {
		offset = addr - load32->p_vaddr + load32->p_offset;
		offset = lseek(core_fd, offset, SEEK_SET);
		read(core_fd, &val, sizeof(u32));

		printf("%8lx: %08lx\n", addr, val);
	} else if (nd->flags == KDUMP_ELF64) {
		offset = addr - load64->p_vaddr + load64->p_offset;
		offset = lseek(core_fd, offset, SEEK_SET);
		read(core_fd, &val, sizeof(ulong));

		printf("%016lx: %016lx\n", addr, val);
	}
}

static void cmd_info(void)
{
	int i;
	Elf32_Phdr *load32;
	Elf64_Phdr *load64;

	if (nd->flags == KDUMP_ELF32) {
		for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf32_Phdr(nd->load32 + i, ELFSTORE + i);
		for (i = 0; i < nd->num_pt_load_segments; i++) {
			load32 = nd->load32 + i;
			printf("vaddr: %08x - %08x\n",
			       load32->p_vaddr,
			       load32->p_vaddr + load32->p_filesz);
		}
	} else if (nd->flags == KDUMP_ELF64) {
		for (i = 0; i < nd->num_pt_load_segments; i++)
			dump_Elf64_Phdr(nd->load64 + i, ELFSTORE + i);
		for (i = 0; i < nd->num_pt_load_segments; i++) {
			load64 = nd->load64 + i;
			printf("vaddr: %016lx - %016lx\n",
			       load64->p_vaddr,
			       load64->p_vaddr + load64->p_filesz);
		}
	}

}

int main(int argc, char **argv)
{
	char buf[BUFSIZE];
	char *ptr, *end = buf + BUFSIZE;

	vmcore_init(argv[1]);

	while (1) {
		printf("Debug> ");

		ptr = fgets(buf, BUFSIZE, stdin);
		while (ptr < end && isspace(*ptr))
			ptr++;

		if (!strncmp(ptr, "info", 4)) {
			cmd_info();
		} else if (!strncmp(ptr, "rd", 2)) {
			ptr += 2;
			while (isspace(*ptr))
				ptr++;
			ulong val = strtoul(ptr, NULL, 16);
			printf("val: %lx\n", val);
			cmd_rd(val);
		} else if (!strncmp(ptr, "quit", 4)) {
			break;
		}
	}

	vmcore_deinit();

	return 0;
}
