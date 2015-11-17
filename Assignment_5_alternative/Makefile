
###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 5                                                             #
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
#   Usage: This Makefile compiles the module `module_masker.c`                #
#                                                                             #
###############################################################################

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h
obj-m += module_masker.o

all:
	$(SYSMAP_SCRIPT)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:	all
	insmod module_masker.ko

uninstall:
	rmmod module_masker.ko
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

sysmap:
	$(SYSMAP_SCRIPT)

