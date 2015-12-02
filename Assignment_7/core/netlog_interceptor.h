#ifndef __NETLOGGER_INTERCEPTOR__
#define __NETLOGGER_INTERCEPTOR__

#include "core.h"

void interceptor_init(struct orig *original_syscalls);
void interceptor_exit(void);
//void netlogger_command(char *cmd);

#endif
