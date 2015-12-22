
###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 9                                                             #
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
#   Usage: This Makefile compiles the module `port_knocker.c`                 #
#                                                                             #
###############################################################################

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h

KDIR = /lib/modules/$(shell uname -r)/build
TARGET = port_knocker

obj-m += $(TARGET).o
ccflags-y = -Wno-unused-function

all:	sysmap
	make -C $(KDIR) M=$(PWD) modules
	@echo "\nPort knocker successfully compiled\n"

clean:
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nUseless files successfully deleted\n"

install:	all
	insmod $(TARGET).ko
	@echo "\nPort knocker successfully installed\n"

uninstall:
	rmmod $(TARGET).ko
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nPort knocker successfully uninstalled\n"

sysmap:
	$(SYSMAP_SCRIPT)
	@echo "\nSysmap header file successfully created\n"

