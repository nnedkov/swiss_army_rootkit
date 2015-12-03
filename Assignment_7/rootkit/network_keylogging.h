
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: network_keylogging.h                                            */
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
/*   Usage: Header file for module `network_keyloging.c`                       */
/*                                                                             */
/*******************************************************************************/

#ifndef __NETWORK_KEYLOGGING__
#define __NETWORK_KEYLOGGING__


/* Declaration of functions */
int network_keylogging_init(int);
int network_keylogging_exit(void);

asmlinkage long network_keylogging_read_syscall(unsigned int, char __user *, size_t);

#endif
