CCFLAGS += -g -gdb -O0
ccflags-y += -g -O0
obj-m = dm-mintegrity.o
KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

