obj-m := basilisk.o
basilisk-objs := src/main.o src/utils.o src/crc32.o src/king.o src/stealth_helper.o src/ftrace_helper.o src/comms.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	gcc -o client src/client.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm client
