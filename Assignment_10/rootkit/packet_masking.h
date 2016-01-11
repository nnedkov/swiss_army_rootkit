
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: packet_masking.h                                                */
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
/*   Usage: Header file for module `packet_masking.c`                          */
/*                                                                             */
/*******************************************************************************/

#ifndef __PACKET_MASKING__
#define __PACKET_MASKING__


/* Declaration of functions */
int packet_masking_init(int);
int packet_masking_exit(void);

int mask_packets(char *);
int unmask_packets(char *);

#endif
