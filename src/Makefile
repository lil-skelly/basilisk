obj-m := basilisk.o
basilisk-objs := main.o utils.o crc32.o king.o stealth_helper.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	gcc -o client client.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

