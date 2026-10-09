We had :
n = 16380649768533394557837493376413306403300053927332145442950164332328030751564185489519565597585555867737606727528343
e1 = 65537
e2 = 65539
c1 = 13717084049277399427945358975177210874446528287993178469838547381506741616766449871863462627142297960244208456711847
c2 = 4601321998457411971134687661444766716276847022305030736758227088246554672740623255330037934526510403437754437399162



This attacks exploit a vulnerability in RSA when the same modulus (n) is used with two different public keys (e1 and e2) to encrypt the same message.

We can find the decrypted message with this equation :

m = c1\*\*u + c2\*\*v



With u and v such that :

e1\*u + e2\*v = 1



This is the Bézout’s Identity, it states that for any two integers a and b with greatest common divisor d, there exist integers u and v such that:

a\*u + b\*v = d



For this vulnerability to work we need to have d = 1. d is equal to gcd(a,b), here gcd (65539,65537) = 1 so it works.



We now use the Extended Euclidean Algorithm to find u and v that works with e1 and e2. Here is my algorithm in python :
```py
def extended_euclidean(a, b):
   u, v, u1, v1 = 1, 0, 0, 1
   while b != 0:
       q = a // b
       r = a % b
       a, b = b, r
       u, u1 = u1, u - q * u1
       v, v1 = v1, v - q * v1
   return a, u, v
pgcd, u, v = extended_euclidean(65537, 65539)
print(f"pgcd = {pgcd}, u = {u}, v = {v}")
```
We found u = 32769 and v = -32768



We now just need to decrypt with m = c1\*\*u + c2\*\*v :
```
from binascii import unhexlify

n = 16380649768533394557837493376413306403300053927332145442950164332328030751564185489519565597585555867737606727528343

c1 = 13717084049277399427945358975177210874446528287993178469838547381506741616766449871863462627142297960244208456711847
c2 = 4601321998457411971134687661444766716276847022305030736758227088246554672740623255330037934526510403437754437399162

u = 32769
v = -32768

m = (pow(c1, u, n) * pow(c2, v, n)) % n

m_hex = hex(m)[2:]

message = unhexlify(m_hex).decode('utf-8')
print("The message is :", message)
```

And we just found the flag : OWASP{v0rm1r_tw1st3d_rsa_l34ks_th3_s0ul}
