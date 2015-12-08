#ifndef __CORE_H__
#define __CORE_H__

#include <linux/list.h>

void register_callback(unsigned int callback_nr, void *callback);
void deregister_callback(unsigned int callback_nr, void *callback);

struct callback {
	void *cb;
	struct list_head list;
};

#endif
