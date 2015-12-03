
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: covert_channel.h                                                */
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
/*   Usage: Header file for module `covert_channel.c`                          */
/*                                                                             */
/*******************************************************************************/

#ifndef __COVERT_CHANNEL__
#define __COVERT_CHANNEL__


/* Declaration of functions */
int covert_channel_init(int);
int covert_channel_exit(void);

asmlinkage long covert_channel_read_syscall(unsigned int, char __user *, size_t);

#endif
