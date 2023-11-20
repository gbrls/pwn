```console
# compiling
gcc -nostdlib file.s -o file
# disassemble the executable sections
objdump -d file
# output just the .text section to another file
objcopy --dump-section .text=file.bin file
```
