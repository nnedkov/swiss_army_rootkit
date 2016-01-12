
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: core.h                                                          */
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
/*   Usage: Header file for `core.c`                                           */
/*                                                                             */
/*******************************************************************************/

#ifndef __CORE_H__
#define __CORE_H__


void register_callback(unsigned int, void *);
void deregister_callback(unsigned int, void *);

void disable_write_protect_mode(void);
void enable_write_protect_mode(void);

void unload_module(void);
#endif
