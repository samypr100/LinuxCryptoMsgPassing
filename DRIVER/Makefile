#
# compile the character device
#
obj-m := char.o

#
# Since we are using our custom kernel, we can build
# against that version
#
KDIR := /lib/modules/$(shell uname -r)/build

#
# Present working directory
#
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	#gcc -o userprogram userprogram.c
clean:
	#rm -f userprogram
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
