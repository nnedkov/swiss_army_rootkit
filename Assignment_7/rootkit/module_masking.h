
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: module_masking.h                                                */
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
/*   Usage: Header file for module `module_masking.c`                          */
/*                                                                             */
/*******************************************************************************/

#ifndef __MODULE_MASKING__
#define __MODULE_MASKING__


/* Declaration of functions */
int module_masking_init(int);
int module_masking_exit(void);

void mask_module(void);
void unmask_module(void);

#endif
