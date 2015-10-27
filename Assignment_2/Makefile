
###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 2                                                             #
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
#   Date: October 2015                                                        #
#                                                                             #
#   Usage: This Makefile compiles the module `interceptor.c`                  #
#                                                                             #
###############################################################################

SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h
obj-m += interceptor.o

all:
	./$(SYSMAP_SCRIPT)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm $(SYSMAP_HEADER)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
