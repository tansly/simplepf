obj-m := simplepf.o 
simplepf-objs := main.o chains.o proc.o

KDIR  := ~/src/linux
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
