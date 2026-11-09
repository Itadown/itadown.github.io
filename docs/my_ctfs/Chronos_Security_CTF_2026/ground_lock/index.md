---
title: Ground Lock
tags: 
    - Reverse Engineering
---

# Ground Lock

A response team recovered the ground-maintenance utility used to service the GRIFFON-FC drones an Ash Army proxy flies over the Operation Dawn theatre. The accepted service code is needed before equipment handover.

Recover that code. This is a constructed software case: the attachment is a Linux utility, not flight-controller firmware or a hardware dump, and static analysis is enough. Attachment: `fcunlock`, Linux x86-64 ELF, 682,600 bytes, SHA-256 `9634a7c4c4769a21eb921125a3d1b0ef560e3f4ed0202efa860861f0d2922399`.

Submit `CSCTF{<service-code>}` with the exact 24 code bytes and case.

---
First I opened the binary in `Ghidra` to find an interesting string in `Defined Strings` : 
* `CSCTF{%.*s}`

Tracing its reference led to `FUN_004016da`, which is clearly the `main` function of the executable. This is confirmed by the usage message printed at the end of the function (`usage: %s <service-code>\n`) and it is being passed as the primary function pointer to `__libc_start_main` inside `entry`.
```C
undefined8 FUN_004016da(int param_1,undefined8 *param_2)

{
  long lVar1;
  bool bVar2;
  undefined8 uVar3;
  long lVar4;
  int local_24;
  ulong local_20;
  ulong local_18;
  
  if (param_1 == 2) {
    lVar1 = param_2[1];
    lVar4 = thunk_FUN_0041e900(lVar1);
    if (lVar4 == 0x18) {
      bVar2 = true;
      for (local_18 = 0; local_18 < 3; local_18 = local_18 + 1) {
        local_20 = 0;
        for (local_24 = 0; local_24 < 8; local_24 = local_24 + 1) {
          local_20 = local_20 |
                     (ulong)*(byte *)(lVar1 + local_18 * 8 + (long)local_24) <<
                     ((byte)(local_24 << 3) & 0x3f);
        }
        lVar4 = FUN_00401655(local_20);
        if (lVar4 != *(long *)(&DAT_00479020 + (local_18 + 4) * 8)) {
          bVar2 = false;
        }
      }
      if (bVar2) {
        FUN_00410460("GRIFFON-FC ground-maintenance interlock released.");
        FUN_0040a170("Maintenance token: CSCTF{%.*s}\n",0x18,lVar1);
        uVar3 = 0;
      }
      else {
        FUN_00410460("ACCESS DENIED");
        uVar3 = 1;
      }
    }
    else {
      FUN_00410460("ACCESS DENIED");
      uVar3 = 1;
    }
  }
  else {
    FUN_0040a0b0(PTR_DAT_004a56c8,"usage: %s <service-code>\n",*param_2);
    uVar3 = 2;
  }
  return uVar3;
}
```

Inside `main`, the program validates the length of the input argument (`lVar1`) using a wrapper function `thunk_FUN_0041e900` (which behaves like `strlen`) :
```C
    lVar4 = thunk_FUN_0041e900(lVar1);
    if (lVar4 == 0x18) {
```

We can also see a print buffer size on `lVar1` :
```C
        FUN_0040a170("Maintenance token: CSCTF{%.*s}\n",0x18,lVar1);
```

Now, we need to understand the loop with its conditions :
```C
      bVar2 = true;
      for (local_18 = 0; local_18 < 3; local_18 = local_18 + 1) {
        local_20 = 0;
        for (local_24 = 0; local_24 < 8; local_24 = local_24 + 1) {
          local_20 = local_20 |
                     (ulong)*(byte *)(lVar1 + local_18 * 8 + (long)local_24) <<
                     ((byte)(local_24 << 3) & 0x3f);
        }
        lVar4 = FUN_00401655(local_20);
        if (lVar4 != *(long *)(&DAT_00479020 + (local_18 + 4) * 8)) {
          bVar2 = false;
        }
      }
```

It is important to keep `bVar2` at `true` so that we can enter in the next condition bellow the loop and get the flag.

We can see that `local_18` is an iterator from `0 to 2` and `local_24` is an iterator too from `0 to 7`, so it id doing 24 iterations. `local_20` is retrieving 8 chars we can translate the line by this : `local_20[local_18 + local_24] = lVar1[local_18 + local_24];`
More specifically `local_20` is doing an `OR` to combine bytes together and it combining the bytes of `lVar1` into a single 64-bit integer (`ulong`) per block. 

Specifically, the expression reads the character at index `lVar1[local_18 * 8 + local_24]`, casts it to 64 bits, and shifts it to its corresponding byte position. The term `local_24 << 3` multiplies the current byte index (0 to 7) by 8 to convert it into a bit offset (0, 8, 16, ..., 56 bits). The mask `& 0x3f` ensures this bit offset remains within 6 bits (0 to 63 bits), matching x86-64 CPU architectural shift limits for a 64-bit register. The main shift operator `<<` then moves the byte to that exact bit position, and the bitwise `OR` (`|`) merges it into `local_20` without modifying already inserted bytes, effectively packing 8 ASCII characters into a 64-bit little-endian value for each of the 3 iterations.

Each 8-bytes block (`local_20`) constructed from the input token is passed to `FUN_00401655` before being compared against a target value in memory :
```C
ulong FUN_00401655(ulong param_1)

{
  ulong uVar1;
  
  uVar1 = (param_1 ^ param_1 >> 0x21) * -0xae502812aa7333;
  uVar1 = (uVar1 ^ uVar1 >> 0x21) * -0x3b314601e57a13ad;
  return uVar1 ^ uVar1 >> 0x21;
}
```
It performs non-linear bit mixing using bitwise XORs, right shifts by 33 bits (`0x21`), and 64-bit multiplications.

Since shifting right by 33 bits zeros out more than half of a 64-bit integer `33 * 2 = 66 > 64`, applying `x ^ (x >> 33)` a second time completely undoes the first operation. Multiplication by an odd 64-bit constant K modulo $2^{64}$ is inverted by multiplying by K's modular multiplicative inverse $K^{-1} \pmod{2^{64}}$, computed using `pow(K, -1, 2**64)` in Python.

We now need to retrieve the data index (`DAT_00479020`, so it is `0x79020` because Ghidra always starts with an offset of `0x400000`) in the Ghidra code and inverse everything in python :
```python
import struct

# fmix64 64-bit unsigned constants
MASK = 0xFFFFFFFFFFFFFFFF
K1 = (0 - 0xae502812aa7333) & MASK    # 0xFF51AFD7ED558CCD
K2 = (0 - 0x3b314601e57a13ad) & MASK  # 0xC4CEB9FE1A85EC53

# Modular multiplicative inverses modulo 2^64
INV_K1 = pow(K1, -1, 2**64)
INV_K2 = pow(K2, -1, 2**64)

def unmix64(h: int) -> int:
    """ Exact mathematical inverse of FUN_00401655 """
    # Inverse of step 3: uVar1 ^ (uVar1 >> 33)
    h = (h ^ (h >> 33)) & MASK
    
    # Inverse of step 2: * K2
    h = (h * INV_K2) & MASK
    
    # Inverse of step 2 (XOR part): uVar1 ^ (uVar1 >> 33)
    h = (h ^ (h >> 33)) & MASK
    
    # Inverse of step 1: * K1
    h = (h * INV_K1) & MASK
    
    # Inverse of step 1 (XOR part): param_1 ^ (param_1 >> 33)
    h = (h ^ (h >> 33)) & MASK
    
    return h

# 1. Read target hashes directly from the binary file
with open("fcunlock", "rb") as f:
    data = f.read()

# Base file offset: Ghidra Address (0x479020) - ELF Base (0x400000) = 0x79020
base_file_offset = 0x79020

target_hashes = []
for local_18 in range(3):
    # Exact C calculation: &DAT_00479020 + (local_18 + 4) * 8
    offset = base_file_offset + (local_18 + 4) * 8
    
    # Extract 8 bytes and unpack into a uint64 integer (Little-Endian)
    val = struct.unpack("<Q", data[offset:offset + 8])[0]
    target_hashes.append(val)

print(f"[+] Hashes extracted from binary: {[hex(h) for h in target_hashes]}")

# 2. Reconstruct the 24-character token
token = ""
for target in target_hashes:
    val64 = unmix64(target)
    # Pack 64-bit integer back into 8 ASCII bytes (Little-Endian)
    token += struct.pack("<Q", val64).decode('latin-1')

print(f"[+] Extracted Token: {token}")
print(f"[+] Final Flag     : CSCTF{{{token}}}")
```
And here is the flag : `CSCTF{HALCYON_1B5FC6D72036689A}`
