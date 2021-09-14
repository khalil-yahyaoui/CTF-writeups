from random import randint
from math import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import *
import re 
def forgery(y: int):
    e = randint(1, p-1)
    r = y*pow(g,e,p) % p
    s = -r % (p - 1)
    m = (e*s) % (p-1)
    m += (bytes_to_long(b'Felicity_Cisco_both') << 1200)
    M = hex(m)[2:]
    return(M,r,s)

d = re.compile(r"\d+")
r = remote("crypto.chal.csaw.io" ,5006)
p , g , y = [ int(i) for i in d.findall(r.recvuntil(b"\n").decode()) ] 
MASK = (2**p.bit_length() - 1)
M, r, s = forgery(y)
r.recvuntil(b"Answer: ")
r.sendline(M.encode())
r.recvuntil(b"r: ")
r.sendline(str(r))
r.recvuntil(b"s: ")
r.sendline(str(s))

print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
