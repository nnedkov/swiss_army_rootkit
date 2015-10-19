
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 1                                                             */
/*                                                                             */
/*   Filename: simple_module.c                                                 */
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
/*   Usage: This kernel module outputs welcome and goodbye messages when it    */
/*          is loaded and unloaded respectively. Additionaly, when loaded,     */
/*          it outputs the number of processes in the system.                  */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>   /* Needed by all modules */
#include <linux/kernel.h>   /* Needed for KERN_INFO */
#include <linux/sched.h>    /* Needed for for_each_process macro */


void print_nr_procs(void);


/* Initialization function which is called when the module is insmoded into
   the kernel */
int init_module(void)
{
	char *welcome_msg = "Hello!\n"
						"My name is Rootkit!\n"
						"Soon your machine will be my pet...\n"
						"Mouaxaxaxaxaxa!\n";

	printk(KERN_INFO "%s\n", welcome_msg);

	print_nr_procs();

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module is rmmoded */
void cleanup_module(void)
{
	char *goodbye_msg = "Bye bye!\n"
						"See you when I see you...\n"
						"Moua mouaxaxaxaxaxa!";

	printk(KERN_INFO "%s\n", goodbye_msg);
}


void print_nr_procs(void)
{
	int nr_procs = 0;
	struct task_struct *task;

	for_each_process(task)
		nr_procs++;

	printk(KERN_INFO "Current number of processes in the system is: %d\n", nr_procs);
}

