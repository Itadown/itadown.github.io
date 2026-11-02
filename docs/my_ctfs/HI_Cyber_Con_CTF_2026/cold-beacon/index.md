---
title: Cold Beacon
tags:
  - Reverse Engineering
---

# Cold Beacon

## Challenge Overview

Evidence tag IR-2231-A, pulled off a workstation mid-engagement. One file, no other artifacts recovered, no notes from the box owner.

It expects one argument: `./cold-beacon <key>`. With the right key it prints the config it was carrying; otherwise it just says it's sealed.

Linux x86-64 ELF.

Files: [cold-beacon.zip](cold-beacon.zip)

SHA-256: `a01791f8259c7bcf1eb07f578abc686b2a4ab78d4fe410f565c74624e52610d8`

Flag Format: `hiCTF{}`

---

## Exploit

I first started by executing the file with a random input to see the output :
```bash
$ ./cold-beacon test
config sealed
```

Seeing the `config sealed` output, I ran `strings` on the binary to search for where it might be stored, along with any other interesting text :
```bash
$ strings cold-beacon
[...]
00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899
[...]
954<3=z)?;6?>P
5&t%k
vRQ>
8STs
LwH'
@TracerPid:
@/proc/self/status
;*3$"
GCC: (GNU) 16.1.1 20260515 (Red Hat 16.1.1-2)
GCC: (GNU) 16.2.1 20260819 (Red Hat 16.2.1-2)
AV:4p1314
RV:running gcc 16.1.1 20260515
BV:annobin gcc 16.1.1 20260515
GW:0x7d60562 ../sysdeps/x86/abi-note.c
[...]
```

I opened the first strings I found intersting in Ghex to find out `!"#$%&'()0123456789@ABCDEFGHIPQRSTUVWXY``abcdefghipqrstuvwxy`, suggesting the use of a custom alphabet or encoding scheme. 

Next, I opened the executable in Ghidra and searched the `Defined Strings` view for `954<3=z)?;6?>P`. Checking its cross-references brought me to function `FUN_004041f9`, where the string is decoded at runtime via an `XOR` operation with `0x5a` :
```rust
*(byte *)(local_18._8_8_ + 8 + lVar1) = "954<3=z)?;6?>P"[lVar1] ^ 0x5a;
```

To verify the obfuscated string, I reversed the `XOR` transformation using `Python` :
```bash
$ python3 -c 'print("".join(chr(ord(c)^0x5a) for c in "954<3=z)?;6?>P"))'
config sealed
```

This confirmed that `FUN_004041f9` decodes and prints the `config sealed` message encountered during execution. I renamed the function from `FUN_004041f9` to `config_sealed`. 

---

### Tracing FUN_00404271

With `config_sealed` renamed, I went to its only caller `FUN_00404271` and I started reading it top to bottom :
```c
auVar13 = FUN_00403a6a();
lVar6 = auVar13._8_8_;
```

`FUN_00403a6a` returns 16 bytes. Ghidra packs them into `auVar13`. The `._8_8_` notation means "the 8 bytes starting at offset 8", Nim (we can confirm it is Nim by looking at the `Defined Strings`) returns multiple values from functions by packing them into a 128-bit SSE register, so `auVar13._0_8_` is the first value and `auVar13._8_8_` is the second.

Next, there is :
```c
if (auVar13._0_8_ == 1) {
  FUN_00403342(&local_98, *(undefined8 *)(lVar6 + 8), *(undefined8 *)(lVar6 + 0x10));
  FUN_004031df(lVar6 + 8);
  bVar11 = local_98 == 0x18;
}
```

I looked at `FUN_00403342` :
```c
void FUN_00403342(undefined8 *param_1, undefined8 param_2, undefined8 param_3)
{
  [...]
  *param_1 = param_2;
  param_1[1] = param_3;
  return;
}
```

It just stores `param_2` and `param_3` into the two slots of `param_1`. So after the call, `local_98 = *(lVar6 + 8)` and the next slot gets `*(lVar6 + 0x10)`.

The `strings` output earlier showed Nim build metadata. Nim strings are heap structs with layout `[length : 8 bytes][char data...]`. That means `lVar6` is the Nim string struct for argv[1], `lVar6 + 8` is the length field, and `lVar6 + 0x10` is a pointer to the characters. After `FUN_00403342`, `local_98` holds the key length.

```c
bVar11 = local_98 == 0x18;   // 0x18 = 24
```

`bVar11` is true only if the key is exactly 24 characters. That's the first gate.

The full chain visible from here :
```c
cVar1 = FUN_00403aec();
if (*(char *)(in_FS_OFFSET + -0x68) == '\0') {
  if (bVar11) {
    cVar2 = FUN_00403cff(local_98, local_90);    // gate 2
    if (cVar2 != '\0') {
      cVar2 = FUN_00403dc4(local_98, local_90);  // gate 3
      if ((cVar2 == '\x01') && (cVar1 == '\0')) { // cVar1 from FUN_00403aec = gate 4
        // crypto --> flag
      }
    }
  }
  [...]
}
config_sealed();
```

Four gates. Fail any one, fall to `config_sealed`.

---

### Gate 2, reading FUN_00403cff from scratch

I opened the function knowing only that it receives the key length and a pointer to the key string :
```c
ulong FUN_00403cff(undefined8 param_1, long param_2)
{
  lVar4 = 0;
  lVar5 = 0;
  do {
    cVar1 = (&DAT_00406070)[lVar4];
    in_RAX = CONCAT71((int7)(in_RAX >> 8),cVar1);
```

`DAT_00406070` is an address label Ghidra made up. It's just a byte array somewhere in the binary. We're reading it one byte at a time with `lVar4` as the index.

```c
    if (cVar1 == '\0') {
LAB_00403d22:
      for (uVar3 = 0; (long)uVar3 < (long)(ulong)(byte)(&DAT_00406050)[lVar4]; uVar3++) {
        in_RAX = CONCAT71((int7)(in_RAX >> 8),
                          (byte)in_RAX ^
                          *(byte *)((ulong)(byte)(&DAT_00405fc0)[uVar3 + lVar5] + 8 + param_2));
      }
      bVar6 = (&DAT_00405fa0)[lVar4] == (byte)in_RAX;
```

There's a second array `DAT_00406050`, one byte read from it gives the loop count. A third array `DAT_00405fc0`, one byte read from it gives a value that gets added to `8 + param_2`. Since `param_2` is the Nim string pointer and `+8` skips the length field, this is indexing into the key characters : `key[that_byte]`. The operation done on the key byte is `^` (XOR). A fourth array `DAT_00405fa0` gives the value the result is compared to.

At this point I can name everything just from what each one does in the code :
- `DAT_00406070` : read once per outer iteration --> controls which operation runs --> **op table**
- `DAT_00406050` : controls the inner loop count --> **count table** (how many key bytes per check)
- `DAT_00405fc0` : gives the index into the key --> **index table** (which key byte positions)
- `DAT_00405fa0` : what the result is compared to --> **expected value table**

Reading the other branches confirms the operation types :
```c
      if (cVar1 == '\x01' || cVar1 == '\x04') {
        uVar3 = 0;
        for (in_RAX = 0; in_RAX < (&DAT_00406050)[lVar4]; in_RAX++) {
          uVar3 = uVar3 + *(byte *)((ulong)(byte)(&DAT_00405fc0)[in_RAX + lVar5] + 8 + param_2);
        }
        bVar6 = (&DAT_00405fa0)[lVar4] == (char)uVar3;
```

Same structure but `+` instead of `^`. This branch handles **sum** :
```c
      if (cVar1 == '\x02') {
        uVar2 = *(byte *)((ulong)(byte)(&DAT_00405fc0)[lVar5]     + 8 + param_2)
              * *(byte *)((ulong)(byte)(&UNK_00405fc1)[lVar5]     + 8 + param_2);
```

Two key bytes multiplied. `UNK_00405fc1` is just `DAT_00405fc0 + 1`, the very next byte in the same table, Ghidra gave it a different name because it crossed a boundary it noticed. This handles **product**.

```c
    lVar4 = lVar4 + 1;
    lVar5 = lVar5 + 6;
    if (lVar4 == 0x17) { return 1; }
```

`lVar4` counts iterations, stops at `0x17 = 23`. `lVar5` advances by 6 each time, so each entry in the index table occupies 6 bytes. There are **23 constraints total**, each using a 6-byte slot in the index table.

To read the actual values from these tables, I needed the raw binary bytes. The virtual addresses in Ghidra become file offsets by subtracting the ELF load base. For a standard non-PIE x86-64 binary the load base is `0x400000`, visible in Ghidra under `Window --> Memory Map` where the `.text` segment starts. So :

```
DAT_00406070 --> file offset 0x406070 - 0x400000 = 0x6070
DAT_00406050 --> file offset 0x406050 - 0x400000 = 0x6050
DAT_00405fc0 --> file offset 0x405fc0 - 0x400000 = 0x5fc0
DAT_00405fa0 --> file offset 0x405fa0 - 0x400000 = 0x5fa0
```

```py
with open("cold-beacon", "rb") as f:
    data = f.read()

ops      = list(data[0x6070:0x6070+23])
counts   = list(data[0x6050:0x6050+23])
expected = list(data[0x5fa0:0x5fa0+23])
raw_idx  = list(data[0x5fc0:0x5fc0+23*6])

print("ops :     ", ops)
print("counts :  ", counts)
print("expected :", expected)
print("indices : ", raw_idx)
```

```text
ops :      [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 4, 5, 4, 5]
counts :   [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 6, 6, 6, 6]
expected : [7, 168, 116, 227, 218, 156, 206, 165, 116, 113, 152, 148, 153, 169, 192, 131, 36, 0, 108, 196, 9, 217, 15]
indices :  [5, 6, 255, 255, 255, 255, 9, 10, 255, 255, 255, 255, ...]
```

The `255` values (`0xFF`) in the index table are unused padding. Each slot is always 6 bytes, but `counts[i]` says how many are real, the inner loop stops there and never reads the `0xFF` bytes.

Reading the first three constraints manually to sanity-check :
```text
i=0 : ops[0]=0 (XOR), counts[0]=2, indices=[5,6],    expected=7
     --> key[5] XOR key[6] == 7

i=1 : ops[1]=1 (SUM), counts[1]=2, indices=[9,10],   expected=168
     --> key[9] + key[10] == 168

i=14 : ops[14]=2 (PRODUCT), counts[14]=2, indices=[3,15], expected=192
      --> key[3] * key[15] == 192  (mod 256)
```

---

### Gate 3, reading FUN_00403dc4 from scratch

```c
bool FUN_00403dc4(undefined8 param_1, long param_2)
{
  if ((*(char *)(param_2 + 0x12) == (char)(-0x58 - *(char *)(param_2 + 0x11))) &&
     (*(byte *)(param_2 + 0x1c) ==
      (byte)(*(byte *)(param_2 + 0x14) ^ (byte)*(undefined4 *)(param_2 + 0xc)))) {
    return (byte)(*(byte *)(param_2 + 0x14) + *(char *)(param_2 + 0x15)) == -0x1d;
  }
  return false;
}
```

`param_2` is the same Nim string pointer as before. Nim string layout : `[length : 8 bytes][data...]`, so `param_2 + 8` is `key[0]`, `param_2 + 9` is `key[1]`, and generally `param_2 + 8 + n` is `key[n]`. To convert any offset in the decompiled code to a key index : `index = offset - 8`.

**First condition, left side :**
```c
*(char *)(param_2 + 0x12) == (char)(-0x58 - *(char *)(param_2 + 0x11))
```

Converting offsets : `0x12 - 8 = 10` and `0x11 - 8 = 9`. So this reads `key[10]` and `key[9]`. Rearranging the equation :
```text
key[10] == -0x58 - key[9]
key[10] + key[9] == -0x58
```

`-0x58` as a signed 8-bit value. In unsigned : `256 - 88 = 168`. So :
**`key[9] + key[10] == 168`**

**First condition, right side :**
```c
*(byte *)(param_2 + 0x1c) == (byte)(*(byte *)(param_2 + 0x14) ^ *(undefined4 *)(param_2 + 0xc))
```

Offsets : `0x1c - 8 = 20`, `0x14 - 8 = 12`, `0x0c - 8 = 4`.

**`key[20] == key[12] XOR key[4]`**

**Return value :**
```c
return (byte)(*(byte *)(param_2 + 0x14) + *(char *)(param_2 + 0x15)) == -0x1d;
```

Offsets : `0x14 - 8 = 12`, `0x15 - 8 = 13`. `-0x1d` unsigned = `256 - 29 = 227`.

**`key[12] + key[13] == 227`**

---

### Gate 4, FUN_00403aec : anti-debug

`strings` had shown `/proc/self/status` and `TracerPid :` in the binary (XOR-obfuscated the same way `config sealed` was). This function reads that file and looks for the `TracerPid` field. Under Linux, when a debugger is attached to a process, that field shows the debugger's PID, otherwise it's `0`.

Back in `FUN_00404271` :
```c
cVar1 = FUN_00403aec();
[...]
if ((cVar2 == '\x01') && (cVar1 == '\0')) {
```

`cVar1` must be `0` for execution to continue. With a debugger attached, `FUN_00403aec` returns non-zero, the condition fails, and we fall to `config_sealed`. Since the key was recovered fully statically, this check was never triggered.

---

### Solving the key with Z3

26 constraints, 24 byte-sized unknowns. Not brute-forceable (`256^24` candidates), but a perfect fit for Z3, a constraint solver that takes symbolic variables and a list of equations and finds values satisfying all of them at once.

```py
from z3 import *

ops      = [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 4, 5, 4, 5]
counts   = [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 6, 6, 6, 6]
expected = [7, 168, 116, 227, 218, 156, 206, 165, 116, 113, 152, 148, 153, 169,
            192, 131, 36, 0, 108, 196, 9, 217, 15]
raw_idx  = [5, 6, 255, 255, 255, 255, 9, 10, 255, 255, 255, 255, 10, 11, 255, 255,
            255, 255, 12, 13, 255, 255, 255, 255, 13, 14, 255, 255, 255, 255, 14,
            15, 255, 255, 255, 255, 16, 17, 255, 255, 255, 255, 17, 18, 255, 255,
            255, 255, 18, 19, 255, 255, 255, 255, 19, 20, 255, 255, 255, 255, 20,
            21, 255, 255, 255, 255, 21, 22, 255, 255, 255, 255, 22, 23, 255, 255,
            255, 255, 23, 0, 255, 255, 255, 255, 3, 15, 255, 255, 255, 255, 7, 21,
            255, 255, 255, 255, 11, 19, 255, 255, 255, 255, 4, 12, 20, 255, 255,
            255, 2, 10, 18, 255, 255, 255, 0, 4, 8, 12, 16, 20, 1, 5, 9, 13, 17,
            21, 2, 7, 10, 15, 18, 23, 3, 6, 11, 14, 19, 22]

# strip padding : each constraint uses a 6-byte slot, 0xFF = unused
indices = []
for i in range(23):
    slot = raw_idx[i*6 : i*6+6]
    indices.append([x for x in slot if x != 0xff])

# 24 symbolic 8-bit variables, one per key byte
k = [BitVec(f'k{i}', 8) for i in range(24)]
s = Solver()

# the flag format and key structure suggest printable ASCII
for i in range(24):
    s.add(k[i] >= 0x20, k[i] <= 0x7e)

# 23 constraints from FUN_00403cff
for i in range(23):
    op, exp, idx = ops[i], expected[i], indices[i]
    if op in (0, 3, 5):         # XOR
        xval = BitVecVal(0, 8)
        for j in idx:
            xval = xval ^ k[j]
        s.add(xval == exp)
    elif op in (1, 4):          # SUM mod 256
        sval = BitVecVal(0, 8)
        for j in idx:
            sval = sval + k[j]
        s.add(sval == exp)
    elif op == 2:               # PRODUCT mod 256
        s.add(k[idx[0]] * k[idx[1]] == exp)

# 3 constraints from FUN_00403dc4
s.add(k[9]  + k[10] == 0xa8)
s.add(k[12] + k[13] == 0xe3)
s.add(k[20] == k[12] ^ k[4])

assert s.check() == sat
m = s.model()
key = bytes([m[k[i]].as_long() for i in range(24)])
print(key)
```

```
b'C0ldB34c0n::unl0ck::7a3f'
```

With the key found, running `./cold-beacon C0ldB34c0n::unl0ck::7a3f` directly prints the flag. The pipeline below explains what the binary is actually doing under the hood.

---

### Reconstructing the flag

The key passes all four gates. In `FUN_00404271`, the crypto pipeline then runs :
```c
sha256(puVar9, local_98, local_78);
auVar14 = FUN_00404119(local_78, 0x2f);
lVar7 = auVar14._8_8_;
auVar15 = FUN_004035e4(0x2f);
lVar8 = auVar15._8_8_;
lVar3 = auVar15._0_8_;
lVar5 = 0;
do {
  lVar4 = lVar5 + 1;
  *(byte *)(lVar5 + 8 + lVar8) = (&DAT_00405e40)[lVar5] ^ *(byte *)(lVar5 + 8 + lVar7);
  lVar5 = lVar4;
} while (lVar4 != 0x2f);
puVar10 = local_58;
for (lVar5 = 8; lVar5 != 0; lVar5 = lVar5 + -1) {
  *puVar10 = 0;
  puVar10 = puVar10 + (ulong)bVar12 * -2 + 1;
}
sha256(lVar8 + 8, lVar3);
cVar1 = FUN_00403679(local_58, &DAT_00405e20);
if (cVar1 != '\0') {
  [...]
  FUN_00400f05(stdout, local_88._0_8_, local_88._8_8_);
}
```

**Step 1, SHA-256 of the key :**

`sha256(puVar9, local_98, local_78)` : `puVar9` points to the key data, `local_98` is the length (24), `local_78` is the output buffer.

**Step 2, `FUN_00404119(local_78, 0x2f)` :**

The SHA-256 output is 32 bytes. `0x2f = 47`. This function needs to produce 47 bytes from 32. I opened it in Ghidra :
```c
uVar4 = 0;   // this is a counter
do {
    *(uint *)(lVar3 + 0x28) =
        uVar4 >> 0x18 | (uVar4 & 0xff0000) >> 8 | (uVar4 & 0xff00) << 8 | uVar4 << 0x18;
```

That bitwise expression : `uVar4 >> 0x18 | (uVar4 & 0xff0000) >> 8 | (uVar4 & 0xff00) << 8 | uVar4 << 0x18` rearranges the four bytes of `uVar4` from little-endian (native x86) to big-endian order. It's a manual byte-swap because x86 is little-endian but the counter needs to be appended as big-endian.

```c
    sha256(lVar3 + 8, auVar7._0_8_, local_58);
```

It hashes a block starting at `lVar3 + 8`. That block is the 32-byte SHA-256 output followed by the 4-byte big-endian counter, so the full input is `sha256_output || counter_be`. The result goes into `local_58`.

```c
    while ((long)local_68._0_8_ < param_2) {  // param_2 = 47
        FUN_0040360c(local_68, *(local_58 + lVar1));
        if (lVar1 == 0x1f) break;   // 0x1f+1 = 32 bytes max per round
        lVar1 += 1;
    }
    uVar4 += 1;
```

It appends output bytes until the buffer reaches 47 bytes, then increments the counter and loops if needed. In Python :

```py
import hashlib

def kdf_expand(h, n):
    out = bytearray()
    counter = 0
    while len(out) < n:
        block = h + counter.to_bytes(4, 'big')
        out.extend(hashlib.sha256(block).digest())
        counter += 1
    return bytes(out[:n])

h_key    = hashlib.sha256(b'C0ldB34c0n::unl0ck::7a3f').digest()
expanded = kdf_expand(h_key, 47)
```

**Step 3, XOR loop :**

Returning to `FUN_00404271` :
```c
*(byte *)(lVar5 + 8 + lVar8) = (&DAT_00405e40)[lVar5] ^ *(byte *)(lVar5 + 8 + lVar7);
```

`DAT_00405e40` at file offset `0x5e40`. The loop runs 47 times (`while lVar4 != 0x2f`). XOR the expanded bytes with this mask :

```py
xor_mask = [98, 232, 115, 46, 134, 2, 197, 221, 60, 22, 169, 118, 174, 42, 137,
            145, 212, 161, 142, 209, 18, 231, 64, 95, 191, 177, 53, 38, 116, 37,
            107, 255, 253, 254, 18, 51, 37, 52, 227, 179, 252, 149, 129, 201, 69, 224, 166]

intermediate = bytes([expanded[i] ^ xor_mask[i] for i in range(47)])
```

**Step 4, integrity check :**
```c
cVar1 = FUN_00403679(local_58, &DAT_00405e20);
```

I opened `FUN_00403679` :
```c
undefined8 FUN_00403679(long param_1, long param_2)
{
  long lVar1 = 0;
  do {
    if (*(char *)(param_1 + lVar1) != *(char *)(param_2 + lVar1)) return 0;
    lVar1 += 1;
  } while (lVar1 != 0x20);   // 0x20 = 32
  return 1;
}
```

It compares 32 bytes between two pointers. `local_58` is the SHA-256 of the intermediate result, `DAT_00405e20` (file offset `0x5e20`) is the expected hash. So this checks `sha256(intermediate) == stored_target`.

```py
sha_target = bytes([5, 2, 242, 133, 205, 249, 16, 86, 0, 162, 116, 68, 24, 28,
                    48, 22, 9, 226, 163, 10, 170, 117, 22, 197, 85, 246, 8, 2, 176, 102, 173, 64])

assert hashlib.sha256(intermediate).digest() == sha_target
print(intermediate.decode())
```

The `intermediate` buffer, the 47 bytes produced by the XOR step, is the flag in plaintext. The SHA-256 comparison just confirms everything ran correctly.

Here is the flag : `hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}`
