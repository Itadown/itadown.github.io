---
title: Cipher Cascade
tags:
  - Cryptography
---

# Cipher Cascade

## Challenge Overview

An encrypted transmission was intercepted from a rogue operator. Intelligence suggests the message was encrypted using multiple layers of encoding — a cascade of ciphers, each wrapped around the last. Can you peel back every layer and reveal the hidden flag?

Files: [cipher-cascade.zip](cipher-cascade.zip)

SHA-256: `d7245a4bbf50857739833d75890ae001a9ed5cbee1f7eb5873171f1234c02631`

Flag Format: `hiCTF{}`

---

## Exploit

So I had :
```text
=== INTERCEPTED TRANSMISSION ===
Multiple encryption layers detected.
Peel them back, one by one.

Hint: The outermost layer is reversed.
Layers applied (outermost to innermost): Reverse → Base64 → Hex → ???

Encoded message:
=Q2NxcTM2EzMhZTM2gjNmVTN2MzMjZDNzkzNmVzY2YmNmVTN2MzMjZDNzkzNidzM1cDNwUjN3UzN
```

I went on CyberChef, applied `Reverse`, then `From Base64`, then `From Hex` and finally tried `ROT13` and found out the flag :
[cipher-cascade.png](cipher-cascade.png)

Here is the flag : `hiCTF{l4y3r_by_l4y3r_unw1nd}`