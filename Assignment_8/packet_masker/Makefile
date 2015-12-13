
###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 8                                                             #
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
#   Usage: This Makefile compiles the module `packet_masker.c`                #
#                                                                             #
###############################################################################

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h

KDIR = /lib/modules/$(shell uname -r)/build
TARGET = packet_masker

obj-m += $(TARGET).o
ccflags-y = -Wno-unused-function

all:	sysmap
	make -C $(KDIR) M=$(PWD) modules
	@echo "\nPacket masker successfully compiled\n"

clean:
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nUseless files successfully deleted\n"

install:	all
	insmod $(TARGET).ko
	@echo "\nPacket masker successfully installed\n"

uninstall:
	rmmod $(TARGET).ko
	make -C $(KDIR) M=$(PWD) clean
	@echo "\nPacket masker successfully uninstalled\n"

sysmap:
	$(SYSMAP_SCRIPT)
	@echo "\nSysmap header file successfully created\n"

