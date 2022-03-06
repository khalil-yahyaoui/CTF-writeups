from pwn import * 
import re
from math import floor
from Crypto.Util.number import *


d = re.compile(r"\d+")
host,port = "crypto.challs.pragyanctf.tech" ,5000
r = remote(host,port)
r.recvuntil(b"encrypt: ")
r.sendline(b"E")
n0 = int(d.findall(r.recvuntil(b"\n").decode().strip())[1])
n1 = int(d.findall(r.recvuntil(b"\n").decode().strip())[1])
ct0 = int(d.findall(r.recvuntil(b"\n").decode().strip())[1])
ct1 = int(d.findall(r.recvuntil(b"\n").decode().strip())[1])
t = 800
K = floor(pow(2,n0.bit_length()-t+0.5))
tmp = Matrix([[K,0,n1],[0,K,-n0]])
tmp = tmp.LLL()
a,b = tmp
q0 = xgcd(a[0],n0)[0]
q1 = xgcd(a[1],n1)[0]
p0 = n0 // q0
p1 = n1 // q1

ct0 = ct0 % q0 - 1
d = inverse_mod(p0,(p0-1)*(q0-1))
print(long_to_bytes(pow(ct0,d,n0) % q0))
#p_ctf{s4rk4r_m4i7ra_5h4r3d_MSB}
#Refrence : https://hal.archives-ouvertes.fr/hal-01288914/document (page 6)
