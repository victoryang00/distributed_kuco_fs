obj-m += bentofs.o
bentofs-objs += acl.o dev.o dir.o file.o xattr.o inode.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
