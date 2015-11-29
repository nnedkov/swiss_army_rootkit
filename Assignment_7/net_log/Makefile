SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h
obj-m += netlog_interceptor.o

all:
	./$(SYSMAP_SCRIPT)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install: all
	insmod interceptor.ko

clean:
	rm $(SYSMAP_HEADER)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
