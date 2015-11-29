SYSMAP_SCRIPT = ./sysmap.sh
SYSMAP_HEADER = ./sysmap.h
obj-m += escalator.o

all:
	./$(SYSMAP_SCRIPT)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install: all
	insmod escalator.ko

clean:
	rm $(SYSMAP_HEADER)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
