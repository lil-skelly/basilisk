obj-m += basilisk.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	gcc -o client client.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

