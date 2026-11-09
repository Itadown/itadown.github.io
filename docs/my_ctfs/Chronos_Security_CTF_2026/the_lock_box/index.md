---
title: The lock box
tags: 
    - Reverse Engineering
---

# The lock box

Operation Dawn, annex entry 06. The Ash gate guards run a small field unit at the north canal crossing: give it the pass phrase and it opens the gate or refuses. We took one. It will not tell you the phrase it is waiting for. Work out the phrase it accepts.

Flag format: `CSCTF{...}`

---

Running the binary with no arguments :
```bash
$ ./lockbox 
ASH ARMY GATE LOCK  model 43-K  (field unit, north canal)
usage: gatelock <status|log|open> [phrase]
```

Three subcommands: `status`, `log`, `open`. The goal is clearly to get `open` to accept a valid passphrase.
```bash
$ ./lockbox open password 
GATE: pass phrase refused - crossing barred
```

I tried `ltrace` and `strace` but neither revealed the passphrase directly. I then loaded the binary in Ghidra and found the main function (the first argument of the `libc_start_main` call), here is the main logic of `FUN_001011c0` : 
```C
lVar4 = FUN_00101490(\*(undefined8 \*)(param_2 + 0x10), local_128);
if (lVar4 == 0x21) { 
    uVar5 = 0;
    do {
        pbVar1 = local_128 + uVar5;
        pbVar2 = \&DAT_00102200 + uVar5;
        uVar5 = uVar5 + 1;
        if ((\*pbVar1 ^ 0x5b) != \*pbVar2) goto LAB_00101291;
    } while (uVar5 < 0x21);
    if ((\*pbVar1 ^ 0x5b) == \*pbVar2) {
        puts("the quartermaster laughs - that is last week's code, soldier");
    }
}
LAB_00101291:
if (DAT_00104014 == 0x5a) {
    puts("GATE: pass phrase accepted - crossing open");
    uVar6 = 0;
}
```

The function calculate the length of the entry (`param_2 + 0x10`) and verifies that it is 33 char long (`0x21`). It then XORs each byte with `0x5b` and compares against `DAT_00102200`, if it matches it prints `last week's code` and then checks `DAT_00104014 == 0x5a`. But `DAT_00104014` is not defined here… Something else is setting it up somewhere else. I found it in `_INIT_1` (here is a strip version of it without defined and some last verification) :
```C
void _INIT_1(int param_1, long param_2) {
    if (2 < param_1) {
        iVar2 = strcmp(*(char **)(param_2 + 8), "open");
        if (iVar2 == 0) {
            lVar3 = FUN_00101490(*(undefined8 *)(param_2 + 0x10), local_128);
            if (lVar3 == 0x2c) {
                bVar4 = 1;
                lVar3 = 0;
                bVar1 = true;
                iVar2 = 0x5b;
                do {
                    uVar6 = (uint)lVar3;
                    bVar5 = local_128[lVar3] ^ (byte)iVar2;
                    bVar5 = (bVar5 << (bVar4 & 7) | bVar5 >> 8-(bVar4 & 7))
                            + (&DAT_0010224d)[uVar6 & 7];
                    if (bVar5 != (&DAT_00102255)[lVar3]) {
                        bVar1 = false;
                    }
                    lVar3 = lVar3 + 1;
                    bVar4 = bVar4 + 3;
                    iVar2 = iVar2 + uVar6 + (uint)bVar5;
                } while (lVar3 != 0x2c);
                DAT_00104014 = (-(uint)!bVar1 & 0xffffffbd) + 0x5a;
            }
        }
    }
}
```

This runs before `main` (that was `FUN_001011c0` seen above) as a constructor. It applies the same `open` subcommand check and expect a passphrase of length `0x2c`. Then it XOR each input byte with a mutating key starting at `0x5b`, it left-rotates the result by `(bVar4 & 7)` bits before adding a byte from an 8 byte key schedule at `DAT_0010224d`. Next, it compares against the target byte at `DAT_00102255` and finally sets `DAT_00104014 = 0x5a` if everything matches.

So I just had to invert the algorithm in python and restore the data from `DAT_0010224d` and `DAT_00102255` with the correct length :
```python
data = open('./lockbox', 'rb').read()

key_bytes = data[0x224d:0x224d+8]
target    = data[0x2255:0x2255+0x2c]

bVar4 = 1
iVar2 = 0x5b
result = []

for i in range(0x2c):
    t   = target[i]
    k   = key_bytes[i & 7]
    rot = bVar4 & 7

    bVar5_pre = (t - k) & 0xff
    x         = ((bVar5_pre >> rot) | (bVar5_pre << (8 - rot))) & 0xff
    c         = x ^ (iVar2 & 0xff)
    result.append(c)

    iVar2 = (iVar2 + i + t) & 0xffffffff
    bVar4 = (bVar4 + 3) & 0xff

print(''.join(chr(c) for c in result))
```

And here is the flag : `CSCTF{06_ash_hawk_road_at_garrisoned_38318f}`