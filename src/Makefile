obj-m := simplepf.o 
ccflags-y += -DSIMPLEPF_TEST
simplepf-objs := main.o chains.o

KDIR  := ~/src/linux
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
