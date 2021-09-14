from sage.all import *
from pwn import *
import re
from Crypto.Util.number import *

reg = re.compile(r"\d+")
host = "crypto.chal.csaw.io"
port = 5008

def wiener(n, e):
    """Wiener's attack"""
    n = Integer(n)
    e = Integer(e)
    for f in (e / n).continued_fraction().convergents()[1:]:
        k, d = f.numerator(), f.denominator()
        phi = ((e * d) - 1) / k
        b = -(n - phi + 1)
        dis_sqrt = sqrt(b * b - 4 * n)
        if dis_sqrt.is_integer():
            p = (-b + dis_sqrt) / 2
            q = (-b - dis_sqrt) / 2
            if p < q:
                p, q = q, p
            return (p, q, d)
def fermatfactor(N):
       if N <= 0: return [N]
       if is_even(N): return [2,N/2]
       a = ceil(sqrt(N))
       while not is_square(a^2-N):
         a = a + 1
       b = sqrt(a^2-N)
       return [a - b,a + b]

r = remote(host,port)


#Level 1 : Wiener Attack
print(r.recvuntil(b"\n"))
n,e,c =[ int(i) for i in reg.findall(r.recvuntil(b"plaintext?").decode())]

p,q,d = wiener(n,e)
#r.sendline(long_to_bytes(pow(c,d,n)))
r.sendline(b"Wiener Wiener chicken dinner")
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))

#Level 2 : Fermat Factorization
n,e,c =[ int(i) for i in reg.findall(r.recvuntil(b"plaintext?").decode())]
p,q = fermatfactor(n)
phi = (p-1)*(q-1)
d = inverse_mod(e,phi)
m = long_to_bytes(pow(c,d,n))
#r.sendline(m)
r.sendline(b"Who came up with this math term anyway?")
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))
print(r.recvuntil(b"\n"))

# Level 3 : RSA LSB oracle Attack

n,e,c =[ int(i) for i in reg.findall(r.recvuntil(b"decrypt?").decode())]
upper_limit = n
lower_limit = 0

flag = -1
i = 1

print(r.recvuntil(b"(please respond with an integer)"))
while lower_limit <= upper_limit:
    chosen_ct = (c*pow(2**i, e, n)) % n
    r.sendline(str(chosen_ct).encode())
    print(r.recvuntil(b"The oracle responds with: "))
    output = int(r.recvuntil(b"\n").decode().strip())
    r.sendline(b"yes")
    if output == 0:
        upper_limit = (upper_limit + lower_limit)/2
    elif output == 1:
        lower_limit = (lower_limit + upper_limit)/2
    else:
        break
    i += 1
r.sendline("Totally did not mean to put an oracle there")
#r.sendline(long_to_bytes(flag))


# Level 4 : Partial Key Exposure Attack

r.recvuntil(b"N = ")
N = ZZ(r.recvline().strip(b"\r\n"))
r.recvuntil(b"e = ")
e = ZZ(r.recvline().strip(b"r\n"))
r.recvuntil(b"d0 = ")
d0 = ZZ(r.recvline().strip(b"r\n"))
r.recvuntil(b"c = ")
c = ZZ(r.recvline().strip(b"r\n"))
r.recvuntil(b"d0bits = ")
d0bits = ZZ(r.recvline().strip(b"r\n"))
r.recvuntil(b"nBits = ")
nBits = ZZ(r.recvline().strip(b"r\n"))


known_bits = d0bits
X = var('X')
P.<x> = PolynomialRing(Zmod(N))

for k in range(1, e+1):
    results = solve_mod([e * d0 * X - k * X * (N - X + 1) + k * N == X], 2 ** known_bits)

    for m in results:
        
        f = x * 2 ** known_bits + ZZ(m[0])
        f = f.monic()
        roots = f.small_roots(X = 2 ** (nBits / 2 - known_bits), beta=0.3)

        if roots:
            print(roots)
            x0 = roots[0]
            p = int(gcd(2 ** known_bits * x0 + ZZ(m[0]), N))
            q = N // p
            assert p * q == N
            d = gmpy2.invert(e, (p - 1)*(q - 1))
            print("flag:", long_to_bytes(pow(c, d, N)))
            break

r.recvuntil("What is the plaintext?\r\n")
r.sendline(b"I'll be careful next time to not leak the key")

