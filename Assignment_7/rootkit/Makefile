
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
#   Date: November 2015                                                       #
#                                                                             #
#   Usage: This Makefile compiles the module `rootkit.c`                      #
#                                                                             #
###############################################################################

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h

KDIR = /lib/modules/$(shell uname -r)/build
TARGET = rootkit
obj-m += $(TARGET).o
#$(TARGET)-y := process_masking.o
#file_masker.o
# covert_channel.o file_masking.o privil_escalating.o

all:	$(SYSMAP_HEADER)
	make -C $(KDIR) M=$(PWD) modules
	@echo "Rootkit successfully compiled"

clean:
	make -C $(KDIR) M=$(PWD) clean
	@echo "Useless files successfully deleted"

install:	all
	insmod $(TARGET).ko
	@echo "Rootkit successfully installed"

uninstall:
	rmmod $(TARGET).ko
	make -C $(KDIR) M=$(PWD) clean
	@echo "Rootkit successfully uninstalled"

sysmap:
	$(SYSMAP_SCRIPT)
	@echo "Sysmap header file successfully created"

