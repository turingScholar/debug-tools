#include "defs.h"

static void info_init(void);
static void info_fini(void);

static void cmd_info(void);
static char *help_info[];

static void dump_block_info(void);
static void dump_wq_info(void);
static void dump_task_info(void);

static void dump_task(struct task_context *tc)
{
	char buf[BUFSIZE];
	ulong exec_start;

	fprintf(fp, "TASK %s pid: %ld task_struct: %lx\n",
		tc->comm, tc->pid, tc->task);

	readmem(tc->task + MEMBER_OFFSET("task_struct", "se"), KVADDR, buf,
		STRUCT_SIZE("sched_entity"), "task_struct.se", FAULT_ON_ERROR);

	exec_start = ULONG(buf + MEMBER_OFFSET("sched_entity", "exec_start"));
	fprintf(fp, "exec_start: %ld.%ld\n",
		exec_start / 1000000000, exec_start % 1000000000);

}

static void dump_task_info(void)
{
	struct task_context *tc;
	ulong value;
	int i, ret;

	if (argcnt < 2) {
		fprintf(fp, "Usage: info_task <pid> ...\n");
		return;
	}

	for (i = 1; i < argcnt; i++) {
		ret = str_to_context(args[i], &value, &tc);
		if (ret == STR_INVALID)
			continue;
		tc = pid_to_context(value);
		dump_task(tc);
	}
}

static void dump_uframe(void)
{
	struct task_context *tc, *orig_tc;
	struct arm64_pt_regs pt_regs;
	ulong value, addr, frame[2];
	int ret;

	if (argcnt != 2) {
		fprintf(fp, "Usage: uframe <pid>\n");
		return;
	}

	ret = str_to_context(args[1], &value, &tc);
	if (ret == STR_INVALID) {
		fprintf(fp, "Invalid pid\n");
		return;
	}
	
	if (is_kernel_thread(tc->task)) {
		fprintf(fp, "Kernel thread\n");
		return;
	}

	addr =
	    generic_get_stacktop(tc->task) -
	    machdep->machspec->user_eframe_offset;
	readmem(addr, KVADDR, &pt_regs, sizeof(pt_regs), "task_struct pt_regs",
		FAULT_ON_ERROR);

	orig_tc = tt->current;
	tt->current = tc;

	print_task_header(fp, tc, 0);
	fprintf(fp, "pc: %012llx lr: %012llx\n", pt_regs.pc, pt_regs.regs[30]);
	fprintf(fp, "sp: %012llx fp: %012llx\n", pt_regs.sp, pt_regs.regs[29]);
	fprintf(fp, "%012llx\n", pt_regs.pc);

	frame[0] = pt_regs.regs[29];
	while (in_user_stack(tc->task, frame[0])) {
		readmem(frame[0], UVADDR, frame, sizeof(frame), "user stack fp",
			FAULT_ON_ERROR);
		fprintf(fp, "%012lx\n", frame[1]);
	}

	tt->current = orig_tc;
}

static struct command_table_entry command_table[] = {
	{ "info", cmd_info, help_info, 0 },
	{ "info_blk", dump_block_info, help_info, 0 },
	{ "info_wq", dump_wq_info, help_info, 0 },
	{ "uframe", dump_uframe, help_info, 0 },
	{ NULL },
};

static void __attribute__((constructor))
    info_init(void)
{
	register_extension(command_table);
}

static void __attribute__((destructor))
    info_fini(void)
{
}

/* For bdev_inode.  See block/bdev.c */
#define I_BDEV(inode) (inode - SIZE(block_device))

static void dump_block_info_v2(void)
{
	struct list_data list_data, *ld;
	int i, inode_count;
	ulong bd_sb, name;
	ulong bdev_inode, gendisk, hd_struct;
	char *block_device_buf, *hd_struct_buf;
	char name_buf[BUFSIZE];

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));

	get_symbol_data("blockdev_superblock", sizeof(void *), &bd_sb);
	readmem(bd_sb + OFFSET(super_block_s_inodes), KVADDR, &ld->start,
		sizeof(ulong), "blockdev_superblock.s_inodes", FAULT_ON_ERROR);

	if (empty_list(ld->start))
		return;

	ld->flags |= LIST_ALLOCATE;
	ld->end = bd_sb + OFFSET(super_block_s_inodes);
	ld->list_head_offset = OFFSET(inode_i_sb_list);

	block_device_buf = GETBUF(SIZE(block_device));
	hd_struct_buf = GETBUF(STRUCT_SIZE("hd_struct"));

	fprintf(fp, "%-16s %-16s %s\n", "BLOCK_DEVICE", "GENDISK", "NAME");

	inode_count = do_list(ld);
	for (i = 0; i < inode_count; i++) {
		bdev_inode = I_BDEV(ld->list_ptr[i]);
		readmem(bdev_inode, KVADDR, block_device_buf,
			SIZE(block_device), "block_device buffer",
			FAULT_ON_ERROR);

		gendisk =
		    ULONG(block_device_buf + OFFSET(block_device_bd_disk));
		if (!gendisk)
			continue;

		if (MEMBER_EXISTS("block_device", "bd_part")) {
			hd_struct =
			    ULONG(block_device_buf +
				  MEMBER_OFFSET("block_device", "bd_part"));
			readmem(hd_struct, KVADDR, hd_struct_buf,
				STRUCT_SIZE("hd_struct"), "hd_struct buffer",
				FAULT_ON_ERROR);

			name =
			    ULONG(hd_struct_buf +
				  MEMBER_OFFSET("hd_struct",
						"__dev") + OFFSET(device_kobj) +
				  OFFSET(kobject_name));
			read_string(name, name_buf, BUFSIZE - 1);

		} else {	/* After v5.11 and later */
			if (!MEMBER_EXISTS("block_device", "bd_device")) {
				fprintf(fp,
					"Unable to get kobject of block_device\n");
				goto out;
			}

			name =
			    ULONG(block_device_buf +
				  MEMBER_OFFSET("block_device",
						"bd_device") +
				  OFFSET(device_kobj) + OFFSET(kobject_name));
			read_string(name, name_buf, BUFSIZE - 1);
		}

		fprintf(fp, "%lx %lx %s\n", bdev_inode, gendisk, name_buf);
	}

out:
	FREEBUF(ld->list_ptr);
	FREEBUF(block_device_buf);
	FREEBUF(hd_struct_buf);
}

static void dump_block_info(void)
{
	struct list_data list_data, *ld;
	int i, bdevcnt;
	ulong gendisk, hd_struct, name;
	char *block_device_buf, *hd_struct_buf;
	char name_buf[BUFSIZE];

	if (!kernel_symbol_exists("all_bdevs"))
		return dump_block_info_v2();	/* After v5.9 and later */

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));
	get_symbol_data("all_bdevs", sizeof(void *), &ld->start);
	if (empty_list(ld->start))
		return;

	ld->flags |= LIST_ALLOCATE;
	ld->end = symbol_value("all_bdevs");
	ld->list_head_offset = OFFSET(block_device_bd_list);

	block_device_buf = GETBUF(SIZE(block_device));
	hd_struct_buf = GETBUF(STRUCT_SIZE("hd_struct"));

	fprintf(fp, "%-16s %-16s %s\n", "BLOCK_DEVICE", "GENDISK", "NAME");
	bdevcnt = do_list(ld);

	for (i = 0; i < bdevcnt; i++) {
		readmem(ld->list_ptr[i], KVADDR, block_device_buf,
			SIZE(block_device), "block_device buffer",
			FAULT_ON_ERROR);

		gendisk =
		    ULONG(block_device_buf + OFFSET(block_device_bd_disk));
		if (!gendisk)
			continue;

		hd_struct =
		    ULONG(block_device_buf +
			  MEMBER_OFFSET("block_device", "bd_part"));
		readmem(hd_struct, KVADDR, hd_struct_buf,
			STRUCT_SIZE("hd_struct"), "hd_struct buffer",
			FAULT_ON_ERROR);

		name =
		    ULONG(hd_struct_buf + MEMBER_OFFSET("hd_struct", "__dev") +
			  OFFSET(device_kobj) + OFFSET(kobject_name));
		read_string(name, name_buf, BUFSIZE - 1);

		fprintf(fp, "%lx %lx %s\n", ld->list_ptr[i], gendisk, name_buf);
	}

	FREEBUF(ld->list_ptr);
	FREEBUF(block_device_buf);
	FREEBUF(hd_struct_buf);
}

static void dump_backtrace(void)
{
	char buf[BUFSIZE];
	FILE *sfp;

	open_tmpfile();
	sprintf(buf, "ptype struct list_head");
	if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR)) {
		rewind(fp);

		sprintf(buf, "ptype struct list_head");
		if (!gdb_pass_through(buf, pc->tmpfile2, GNU_RETURN_ON_ERROR))
			error(FATAL, "Invalid data struct\n");
	}
	rewind(fp);

	sfp = pc->saved_fp;
	while (fgets(buf, BUFSIZE, fp))
		fprintf(sfp, "%s", buf);
	close_tmpfile();
}

static void dump_worker_pool(ulong worker_pool)
{
	struct list_data list_data, *ld;
	struct task_context *tc;
	int i, worker_count;
	ulong task;

	ld = &list_data;
	BZERO(ld, sizeof(struct list_data));

	ld->flags |= LIST_ALLOCATE;

	readmem(worker_pool + MEMBER_OFFSET("worker_pool", "workers"), KVADDR,
		&ld->start, sizeof(void *), "worker_pool workers",
		FAULT_ON_ERROR);
	readmem(ld->start + OFFSET(list_head_prev), KVADDR,
		&ld->end, sizeof(void *), "list_head prev", FAULT_ON_ERROR);
	ld->list_head_offset = MEMBER_OFFSET("worker", "node");

	worker_count = do_list(ld);
	for (i = 0; i < worker_count; i++) {
		readmem(ld->list_ptr[i] + MEMBER_OFFSET("worker", "task"),
			KVADDR, &task, sizeof(ulong), "worker task",
			FAULT_ON_ERROR);

		tc = task_to_context(task);
		fprintf(fp, "%5ld %5ld %lx [%s]\n", tc->pid,
			task_to_pid(tc->ptask), task, tc->comm);
	}

	fprintf(fp, "\n");
}

static void dump_wq_info(void)
{
	int i;
	struct syment *sp;
	ulong worker_pool;

	sp = per_cpu_symbol_search("cpu_worker_pools");
	if (!sp) {
		fprintf(fp, "cpu_worker_pools not found\n");
		return;
	}

	for (i = 0; i < kt->cpus; i++) {
		fprintf(fp, "CPU%d:\n", i);
		worker_pool = kt->__per_cpu_offset[i] + sp->value;
		dump_worker_pool(worker_pool);
	}
}

static void cmd_info(void)
{
	dump_task_info();
}

static char *help_info[] = {
	"info",			/* command name */
	"customer defined command",	/* short description */
	"arg ...",		/* argument synopsis, or " " if none */

	"  This command simply echoes back its arguments.",
	"\nEXAMPLE",
	"  Echo back all command arguments:\n",
	"    crash> info hello, world",
	"    hello, world",
	NULL
};
