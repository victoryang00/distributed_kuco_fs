**Development has moved to a github repo [here](https://github.com/smiller123/bentofs).**

This is a kernel module for exposing a safe file operations API to enable safe Rust file systems.

It can be used by Linux kernel file systems implemented using the `bento` Rust crate.

Runs in Linux kernel version 4.15.

This code is based on the FUSE kernel module from Linux kernel version 4.15.

**To compile:**
```
make
```

**To clean:**
```
make clean
```

**To insert module:**
```
sudo insmod bentofs.ko
```

**To remove module:**
```
sudo rmmod bentofs
```
