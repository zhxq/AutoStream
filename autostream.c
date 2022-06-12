/*
 * Adapted from https://github.com/ilammy/ftrace-hook for hook management part.
 */

#define pr_fmt(fmt) "AutoStream: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/blkdev.h>
#include <linux/nvme_ioctl.h>
#include <linux/nvme.h>
#include <linux/moduleparam.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include "nvme.h"

// Uncomment the following line to enable logging to dmesg.
#define DEBUG_MODULE

#ifdef DEBUG_MODULE
#define printdbg(fmt, ...) \
	do { printk(fmt, ## __VA_ARGS__); } while (0)
#define printwmodname(fmt, ...) \
	do { pr_info(fmt, ## __VA_ARGS__); } while (0)
#else
#define printdbg(fmt, ...) \
	do { } while (0)
#define printwmodname(fmt, ...) \
	do { } while (0)
#endif

#define KERNEL_SECTOR_SIZE 512
#define DISK_PAGE_SIZE 4096

MODULE_DESCRIPTION("Block IO Stream ID Tagger");
MODULE_AUTHOR("Xiangqun Zhang <xzhang84@syr.edu>");
MODULE_LICENSE("GPL");
struct chunk_info {
	uint access_cnt;
	uint stream_id;
	uint64_t access_time;
};
/*
 What is accepted as parameter?
	disk_list: disk0n1:1048576:4096:5:16;disk1n1:16777216:8192:7:32
	Diskname:disksize:chunksize:decayperiod:numstreams
	sudo modprobe autostream disk_list="nvme0n1:21474836480:2097152:10:16"
*/


static int disks = 0;
static char** disk_list = NULL;
static char* original_disk_list = NULL;
static uint64_t* disk_size_list = NULL;
static int* chunk_size_list = NULL;
static uint64_t* chunk_num_list = NULL;
static struct chunk_info** chunk_list;
static int* decay_period = NULL;
static int* stream_list = NULL;

static sector_t* prev_end_sector;
static int* prev_stream;


static int disk_list_set(const char *newval, const struct kernel_param *kp)
{
	char* val;
	int i;
	int diskc = 1;
	int processed = 1;
	val = kmalloc(strlen(newval) + 1, GFP_KERNEL);
	original_disk_list = kmalloc(strlen(newval) + 1, GFP_KERNEL);
	strcpy(val, newval);
	strcpy(original_disk_list, newval);
	for (i = 0; i < disks; i++){
		kfree(disk_list[i]);
		kfree(chunk_list[i]);
	}
	kfree(disk_list);
	kfree(chunk_list);
	kfree(disk_size_list);
	kfree(chunk_size_list);
	kfree(chunk_num_list);
	kfree(prev_end_sector);
	kfree(prev_stream);
	kfree(decay_period);
	kfree(stream_list);

	char* tmpstream = val;
	char* tmpprocess;
	char* tmpstream_r = val;
	char* tmpprocess_r;

	// count how many streams we need here
	for (i = 0; val[i] != '\0'; i++){
		if (val[i] == ';'){
			diskc++;
		}
	}
	disk_list = kmalloc_array(diskc, sizeof(char*), GFP_KERNEL);
	chunk_list = kmalloc_array(diskc, sizeof(struct chunk_info*), GFP_KERNEL);
	disk_size_list = kmalloc_array(diskc, sizeof(uint64_t), GFP_KERNEL);
	chunk_size_list = kmalloc_array(diskc, sizeof(int), GFP_KERNEL);
	chunk_num_list = kmalloc_array(diskc, sizeof(uint64_t), GFP_KERNEL);
	prev_end_sector = kmalloc_array(diskc, sizeof(sector_t), GFP_KERNEL);
	prev_stream = kmalloc_array(diskc, sizeof(int), GFP_KERNEL);
	decay_period = kmalloc_array(diskc, sizeof(int), GFP_KERNEL);
	stream_list = kmalloc_array(diskc, sizeof(int), GFP_KERNEL);
	disks = diskc;

	diskc = 0;
	while ((tmpstream = strsep(&tmpstream_r, ";"))) {
		printwmodname("Disk: %d\n", diskc + 1);
		printwmodname("Info: %s\n", tmpstream);
		tmpprocess = tmpstream;
		tmpprocess_r = tmpstream;
		processed = 0;
		while ((tmpprocess = strsep(&tmpprocess_r, ":"))) {
			if (processed == 0){
				// Disk name
				disk_list[diskc] = kmalloc(strlen(tmpprocess) + 1, GFP_KERNEL);
				strcpy(disk_list[diskc], tmpprocess);
				printwmodname("  Disk Name: %s\n", disk_list[diskc]);
			}else if (processed == 1){
				// Size info
				if (kstrtoull(tmpprocess, 10, &disk_size_list[diskc])){
					return -1;
				}
				printwmodname("  Disk size: %llu bytes\n", disk_size_list[diskc]);
			}else if(processed == 2){
				// Chunk Info
				if (kstrtoint(tmpprocess, 10, &chunk_size_list[diskc]) != 0){
					return -1;
				}
				printwmodname("  Chunk size: %d bytes\n", chunk_size_list[diskc]);
				
				chunk_num_list[diskc] = ((disk_size_list[diskc] - 1) / chunk_size_list[diskc]) + 1;
				printwmodname("  Num chunks: %llu\n", chunk_num_list[diskc]);
				chunk_list[diskc] = vmalloc(chunk_num_list[diskc] * sizeof(struct chunk_info));
				
				prev_end_sector[diskc] = -1;
				prev_stream[diskc] = -1;
				for (i = 0; i < chunk_num_list[diskc]; i++){
					chunk_list[diskc][i].access_cnt = 0;
					chunk_list[diskc][i].stream_id = 0;
					chunk_list[diskc][i].access_time = ktime_get_real_ns();
				}
			}else if (processed == 3){
				// Decay period
				if (kstrtoint(tmpprocess, 10, &decay_period[diskc])){
					return -1;
				}
				printwmodname("  Decay period: %ds\n", decay_period[diskc]);
			}else if (processed == 4){
				// Total streams
				if (kstrtoint(tmpprocess, 10, &stream_list[diskc])){
					return -1;
				}
				printwmodname("  Total streams: %ds\n", stream_list[diskc]);
			}
			processed++;
		}
		if (processed != 5){
			return -1;
		}
		diskc++;
	}
	kfree(val);
	return 0;
}
 
static int disk_list_get(char* buffer, const struct kernel_param *kp){
	if (original_disk_list == NULL) return 0;
	strcpy(buffer, original_disk_list);
	return strlen(buffer);
}


static const struct kernel_param_ops param_ops_disk_list = {
	.set	= disk_list_set,
	.get	= disk_list_get,
};

module_param_cb(disk_list, &param_ops_disk_list, NULL, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(disk_list, "Disks to enable AutoStream. Format: disk0n1:1048576:4096:5;disk1n1:16777216:8192:7 - where 1048576 and 16777216 are the max sizes of the disk, 4096/8192 are the chunk sizes, 5s/7s for decay period.");

static int find_disk(const char* disk_name){
	int i = 0;
	if (!virt_addr_valid(disk_name)){
		return -1;
	}
	for (; i < disks; i++){
		//printwmodname("Matching disk %s\n", disk_list[i]);
		if (strstr(disk_name, disk_list[i])){
			printwmodname("Matched disk %s\n", disk_name);
			return i;
		}
	}
	return -1;
}

static void update_stream_table_entry(const char* disk_name, const sector_t sector, const uint data_len){
	int disk_id = find_disk(disk_name);
	struct chunk_info *ci;
	uint64_t chunk;
	uint recency_weight;
	int i = 0;
	if (disk_id < 0){
		return;
	}
	printwmodname("update_stream_table_entry for disk %s, sector %llu, data_len %u\n", disk_name, sector, data_len);
	printwmodname("sector * KERNEL_SECTOR_SIZE = %llu, chunk_size_list[disk_id] = %d\n", (sector * KERNEL_SECTOR_SIZE), chunk_size_list[disk_id]);
	if (chunk_size_list[disk_id] == 0){
		printwmodname("chunk_size_list[disk_id] == 0!");
		return;
	}
	chunk = (sector * KERNEL_SECTOR_SIZE) / chunk_size_list[disk_id];
	printwmodname("Updating stream table entry for disk %s, sector %llu, data_len %u, chunk %llu\n", disk_name, sector, data_len, chunk);
	ci = &chunk_list[disk_id][chunk];
	printwmodname("Old access count for this chunk: %u, new count: %u\n", ci->access_cnt, ci->access_cnt + 1);
	ci->access_cnt += 1;
	recency_weight = 1 << (int)((ktime_get_real_ns() - ci->access_time) / 1000000000 / decay_period[disk_id]);
	if (decay_period[disk_id] == 0){
		printwmodname("decay_period[disk_id] == 0!");
		return;
	}
	printwmodname("Pow exp: %d, final recency_weight = %u\n", (int)((ktime_get_real_ns() - ci->access_time) / 1000000000 / decay_period[disk_id]), recency_weight);
	if (recency_weight == 0){
		printwmodname("recency_weight == 0!");
		return;
	}
	ci->access_cnt = (ci->access_cnt / recency_weight);
	printwmodname("access_cnt = access_cnt/recency_weight: %u\n", ci->access_cnt);
	for (; i < stream_list[disk_id]; i++){
		ci->stream_id = i;
		if (1 << (i + 1) >= ci->access_cnt){
			break;
		}
	}
	printwmodname("Now stream id (log 2): %d\n", i);
	ci->access_time = ktime_get_real_ns();
}

static int get_stream_id(const char* disk_name, const sector_t sector, const uint data_len){
	// First match the disk ID
	int disk_id = find_disk(disk_name);
	int to_stream = 0;
	uint64_t chunk;
	
	if (disk_id < 0){
		return 0;
	}
	printwmodname("Getting stream ID for disk %s, sector %llu, data_len %u\n", disk_name, sector, data_len);
	if (sector == prev_end_sector[disk_id]){
		to_stream = prev_stream[disk_id];
		printwmodname("Using previous stream ID %d\n", to_stream);
	}else{
		if (chunk_size_list[disk_id] == 0){
			printwmodname("get_stream_id chunk_size_list[disk_id] == 0!");
			return 0;
		}
		chunk = (sector * KERNEL_SECTOR_SIZE) / chunk_size_list[disk_id];
		to_stream = chunk_list[disk_id][chunk].stream_id;
		printwmodname("Using stream ID %d from chunk\n", to_stream);
	}
	prev_end_sector[disk_id] = sector + data_len / KERNEL_SECTOR_SIZE;
	prev_stream[disk_id] = to_stream;
	printwmodname("Prev end sector now: %llu, Prev stream now: %d\n", prev_end_sector[disk_id], prev_stream[disk_id]);
	return to_stream + 2;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
					| FTRACE_OPS_FL_RECURSION
					| FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static asmlinkage void (*real_blk_account_io_start)(struct request *rq);

static asmlinkage void fh_blk_account_io_start(struct request *rq)
{
	struct gendisk *rq_disk = rq->rq_disk;
	char* disk_name = rq_disk->disk_name;
	if ((virt_addr_valid(disk_name))){
		unsigned int data_len = blk_rq_bytes(rq);
		sector_t sector = blk_rq_pos(rq);
		update_stream_table_entry(disk_name, sector, data_len);
		rq->write_hint = get_stream_id(disk_name, sector, data_len);
	}
	
	real_blk_account_io_start(rq);
}

#define SYSCALL_NAME(name) (name)

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("blk_account_io_start",  fh_blk_account_io_start,  &real_blk_account_io_start),
};

static int fh_init(void)
{
	int err;
	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	printwmodname("module loaded\n");
	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	printwmodname("module unloaded\n");
}
module_exit(fh_exit);
