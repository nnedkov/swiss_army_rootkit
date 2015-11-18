
###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 6                                                             #
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
#   Date: November 2015                                                       #
#                                                                             #
#   Usage: This Makefile compiles the module `socket_masker.c`                #
#                                                                             #
###############################################################################

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h

KDIR = /lib/modules/$(shell uname -r)/build
TARGET = socket_masker
obj-m += $(TARGET).o

all:	$(SYSMAP_HEADER)
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:	all
	insmod socket_masker.ko

uninstall:
	rmmod socket_masker.ko
	make -C $(KDIR) M=$(PWD) clean

sysmap:
	$(SYSMAP_SCRIPT)

