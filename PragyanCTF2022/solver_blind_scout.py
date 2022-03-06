from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from base64 import b64decode
import os
os.chdir("./crypto/Blind_Scout")

Nkeys = []
e = 65537
for i in range(1, 6):
	with open(f"pub{i}.pem") as f:
		key = RSA.import_key(f.read())
		key = key.n
	Nkeys.append(key)

Ps = []

for i in range(5):
	for j in range(i+1, 5):
		if GCD(Nkeys[i], Nkeys[j]) != 1:
			print(i, j)
			I, J = i, j
			break

P1 = GCD(Nkeys[I], Nkeys[J])
Q1 = Nkeys[I] // P1
assert isPrime(P1) and isPrime(Q1) and Nkeys[I] == P1 * Q1
d1 = inverse(e, (P1-1)*(Q1-1))


P3 = P1
Q3 = Nkeys[J] // P3
d3 = inverse(e, (P3-1)*(Q3-1))

assert isPrime(P3) and isPrime(Q3) and Nkeys[J] == P3 * Q3

for i in range(5):
	if Nkeys[i] % Q1 == 0:
		print(i)

with open("cipher.txt") as f:
	cipher = b64decode(f.read())

cipher = bytes_to_long(cipher)
flag = cipher
flag = pow(flag, d3, P3*Q3)
#flag = pow(flag, d1, P1*Q1)

print(long_to_bytes(flag))
#p_ctf{010100_100000101100_100110100000111010100010100110100010111001010100111000}
# from braille
# p_ctf{I_AM_DAREDEVIL}
