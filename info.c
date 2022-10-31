#include "defs.h"

static void info_init(void);
static void info_fini(void);

static void cmd_info(void);
static char *help_info[];

static struct command_table_entry command_table[] = {
        { "info", cmd_info, help_info, 0},
        { NULL },
};

static void __attribute__((constructor))
info_init(void)
{ 
        register_extension(command_table);
}

static void __attribute__((destructor))
info_fini(void) { }


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
		readmem(bdev_inode, KVADDR, block_device_buf, SIZE(block_device),
			"block_device buffer", FAULT_ON_ERROR);

		gendisk = ULONG(block_device_buf + OFFSET(block_device_bd_disk));
		if (!gendisk)
			continue;

		if (MEMBER_EXISTS("block_device", "bd_part")) {
			hd_struct = ULONG(block_device_buf + MEMBER_OFFSET("block_device", "bd_part"));
			readmem(hd_struct, KVADDR, hd_struct_buf, STRUCT_SIZE("hd_struct"), 
				"hd_struct buffer", FAULT_ON_ERROR);
			
			name = ULONG(hd_struct_buf + MEMBER_OFFSET("hd_struct", "__dev") + 
				OFFSET(device_kobj) + OFFSET(kobject_name));
			read_string(name, name_buf, BUFSIZE-1);

		} else { /* After v5.11 and later */
			if (!MEMBER_EXISTS("block_device", "bd_device")) {
				fprintf(fp, "Unable to get kobject of block_device\n");
				goto out;
			}
			
			name = ULONG(block_device_buf + MEMBER_OFFSET("block_device", "bd_device") + 
				OFFSET(device_kobj) + OFFSET(kobject_name));
			read_string(name, name_buf, BUFSIZE-1);
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
		return dump_block_info_v2(); /* After v5.9 and later */

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

		gendisk = ULONG(block_device_buf + OFFSET(block_device_bd_disk));
		if (!gendisk)
			continue;
		
		hd_struct = ULONG(block_device_buf + MEMBER_OFFSET("block_device", "bd_part"));
		readmem(hd_struct, KVADDR, hd_struct_buf, STRUCT_SIZE("hd_struct"), 
			"hd_struct buffer", FAULT_ON_ERROR);
		
		name = ULONG(hd_struct_buf + MEMBER_OFFSET("hd_struct", "__dev") + 
			OFFSET(device_kobj) + OFFSET(kobject_name));
		read_string(name, name_buf, BUFSIZE-1);
		
		fprintf(fp, "%lx %lx %s\n", ld->list_ptr[i], gendisk, name_buf);
	}

	FREEBUF(ld->list_ptr);
	FREEBUF(block_device_buf);
	FREEBUF(hd_struct_buf);
}

static void cmd_info(void)
{	
	dump_block_info();
}

static char *help_info[] = {
        "info",                        /* command name */
        "customer defined command",   /* short description */
        "arg ...",                     /* argument synopsis, or " " if none */
 
        "  This command simply echoes back its arguments.",
        "\nEXAMPLE",
        "  Echo back all command arguments:\n",
        "    crash> info hello, world",
        "    hello, world",
        NULL
};