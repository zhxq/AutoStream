KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build
ccflags-y := -std=gnu99  -Wno-declaration-after-statement

obj-m += autostream.o

all: clean
	make -C $(KERNEL_PATH) M=$(shell pwd) modules
	make -C $(KERNEL_PATH) M=$(shell pwd) modules_install
	depmod -A

clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) clean