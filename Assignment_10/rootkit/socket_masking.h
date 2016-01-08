
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
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
/*   Date: January 2016                                                        */
/*                                                                             */
/*   Usage: Header file for module `socket_masking.c`                          */
/*                                                                             */
/*******************************************************************************/

#ifndef __SOCKET_MASKING__
#define __SOCKET_MASKING__


/* Declaration of functions */
int socket_masking_init(int);
int socket_masking_exit(void);

int mask_socket(char *, int);
int unmask_socket(char *, int);

#endif
