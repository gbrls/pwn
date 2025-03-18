# Linux kernel heap overflow exploit

### [My writeup with detailed explanations](https://gbrls.github.io/writeups/irisctf2025-checksumz/)

> [!NOTE]
> The exploit source code is [here](https://github.com/gbrls/pwn/blob/main/iris-2025/checksumz/exploit/exploit.c)

This was my first heap overflow exploit, in the userland or kernel. This was also my first kernel exploit.

Huge thanks to [@thotypous](https://github.com/thotypous) for the encouragement and [@0xTen](https://github.com/0xTen) for the guidance and useful materials.


> [!WARNING]
> Original readme below

## Checksumz

This is a kernel pwn challenge. You can find the vulnerable char device at "/dev/checksumz". 

**Warning**: This kernel module has serious security issues, and might crash your kernel at any time. Please don't load this on any system that you actually care about. We recommend using the start script, which will execute the module using qemu.

- Running `$ ./start.sh` will start a linux VM with the module loaded in qemu-system-x86_64. This should be as close as possible to the target challenge server.

- You may use `$ make exploit` to build the exploit script. There are a few ways to get this exploit onto the virtual machine, but an http server in combination with busybox wget is probably the easiest solution.

- If you run `$ ./start.sh --root`, you will get a root shell inside the VM. This might be useful for debugging purposes.

- If you run `$ ./start.sh --debug`, the qemu debug server will be started. You can connect with `$ gdb -x attach.gdb`

### Structure

**artifacts/**  
The compiled kernel, busybox, module and filesystem.  

**chal-module/**  
Source and related files for the challenge module.  

**default/**  
Kernel and busybox config files.  

**exploit/**  
You may build your exploit here.  
