
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
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
/*   Date: January 2016                                                        */
/*                                                                             */
/*   Usage: Header file for module `process_masking.c`                         */
/*                                                                             */
/*******************************************************************************/

#ifndef __PROCESS_MASKING__
#define __PROCESS_MASKING__


/* Declaration of functions */
int process_masking_init(int, pid_t *, int);
int process_masking_exit(void);

int mask_process(pid_t);
int unmask_process(pid_t);

#endif
