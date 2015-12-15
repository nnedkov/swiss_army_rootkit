
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 8                                                             */
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
/*   Date: December 2015                                                       */
/*                                                                             */
/*   Usage: Header file for module `packet_masking.c`                          */
/*                                                                             */
/*******************************************************************************/

#ifndef __PACKET_MASKING__
#define __PACKET_MASKING__


/* Declaration of functions */
void packet_masking_init(void);
void packet_masking_exit(void);

void mask_ip_traffic(char *ip_addr);
void unmask_ip_traffic(char *ip_addr);

#endif
