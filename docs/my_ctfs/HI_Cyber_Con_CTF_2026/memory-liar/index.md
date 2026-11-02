---
title: Memory Liar
tags:
  - Forensics
---

# Memory Liar

## Challenge Overview

A critical workstation on the financial management subnet was suspected of being compromised by an advanced persistent threat (APT). Our tier-1 triage team collected a physical memory capture and ran an automated process audit.

The automated audit reported everything clean: all running processes appear ordinary, can you retrieve the flag?

Files: [memory-liar.zip](memory-liar.zip)

SHA-256: `26a5e19d3e6a3c591e008abf1d644ecab735197d06c5c1e2b4a42e64183c1414`

Flag Format: `hiCTF{}`

---

## Exploit

I first started to analyze the file with `file` and `strings` :
```bash
$ file memory.raw 
memory.raw: data
$ strings memory.raw
[...]
====================================================================
[CONFIDENTIAL - ENDPOINT INCIDENT LOG]
Host Audit: SEC-2026-10-19-094
Status: System integrity validated. No hidden tasks or hooks found.
Forensics Verification Token: hiCTF{th1s_1s_4_f4k3_d3c0y_fl4g_f0r_n00bs_883a1c}
====================================================================
Proc
winxnet.exe
Thre
[...]
```

I could find a fake flag, some named executables with one that seems strange : `winxnet.exe` (surrounded by kernel `Proc` and `Thre`).

The challenge name Memory Liar hints at a rootkit technique. In Windows Kernel forensics we have `pslist` that traverses the official doubly-linked list `ActiveProcessLinks` and `psscan` that scans raw pool memory for `Proc` pool tags.

An attacker using **DKOM** (Direct Kernel Object Manipulation) unlinks the malicious process from `ActiveProcessLinks`, making it invisible to standard process audits while keeping it running.

I performed a manual `psscan` by searching `Proc` pool tags along with their offsets in hexadecimal :
```bash
$ strings -a -t x memory.raw 
 20151c RSDSJ
 201534 ntkrpamp.pdb
 210008 KDBG
 30b004 Proc
 30b174 System
 30c004 Thre
 313004 Proc
 313174 smss.exe
 314004 Thre
 31b004 Proc
 31b174 csrss.exe
 31c004 Thre
 323004 Proc
 323174 wininit.exe
 324004 Thre
 32b004 Proc
 32b174 services.exe
 32c004 Thre
 333004 Proc
 333174 lsass.exe
 334004 Thre
 33b004 Proc
 33b174 svchost.exe
 33c004 Thre
 343004 Proc
 343174 svchost.exe
 344004 Thre
 34b004 Proc
 34b174 explorer.exe
 34c004 Thre
 353004 Proc
 353174 notepad.exe
 354004 Thre
 355000 ====================================================================
 355046 [CONFIDENTIAL - ENDPOINT INCIDENT LOG]
 35506e Host Audit: SEC-2026-10-19-094
 35508e Status: System integrity validated. No hidden tasks or hooks found.
 3550d3 Forensics Verification Token: hiCTF{th1s_1s_4_f4k3_d3c0y_fl4g_f0r_n00bs_883a1c}
 355124 ====================================================================
 35d004 Proc
 35d174 winxnet.exe
 35e004 Thre
 35f000 ROOT9
 35f015 &96m0
 35f01b (31l36
 35f022 n-/m>n..
 35f02b 1l.)
 35f030 >/m..
 35f036 >5n>6
 35f03c j>n<d; 
 35f050 c2.darkshadow-apt.org:8443
 35f070 OP_SHADOW_LIAR_ACTIVE
```

I can clearly see that `winxnet.exe` is separated from the other executables, it was unlinked from `ActiveProcessLinks` via DKOM to bypass the standard detection.
I filtered just the `Proc` elements with their hexadecimal addresses that'll be useful to analyze the hexadecimal around some executables.

There is some strange data after `ROOT9` that we can analyze a bit more :
```bash
$ hexdump -C -s 0x5f000 -n 96 winxnet.dmp
0005f000  52 4f 4f 54 39 05 00 00  5d 00 00 00 33 00 00 00  |ROOT9...]...3...|
0005f010  35 34 1e 09 1b 26 39 36  6d 30 02 28 33 31 6c 33  |54...&96m0.(31l3|
0005f020  36 02 6e 2d 2f 6d 3e 6e  2e 2e 02 31 6c 2e 29 02  |6.n-/m>n...1l.).|
0005f030  3e 2f 6d 2e 2e 02 3e 35  6e 3e 36 02 6a 3e 6e 3c  |>/m...>5n>6.j>n<|
0005f040  64 3b 20 00 00 00 00 00  00 00 00 00 00 00 00 00  |d; .............|
0005f050  63 32 2e 64 61 72 6b 73  68 61 64 6f 77 2d 61 70  |c2.darkshadow-ap|
```

We can see the 8 bytes header, there is 4 bytes that seems to be a variable (defined wit `0x5d`) and then another variable that seems to be the length of the next one, it is `0x33` that is equal to 51 and there is 51 bytes in the next variable (with 13 bytes of padding at the end).

It seems like an operation had been made on the variable that starts at `0x0005f010`.

The buffer content (`54...&96m0.(31l36...`) consists of printable ASCII mixed with low control characters (`0x1e`, `0x09`, `0x1b`, `0x02`). This specific byte distribution rules out high-entropy encryption (like AES, which produces uniform binary data) and strongly indicates single-byte XOR obfuscation.

Knowing that the CTF flag format starts with `hiCTF{`, we perform a Known-Plaintext Attack against the first 6 bytes of the buffer (`0x35 0x34 0x1e 0x09 0x1b 0x26`):
```bash
$ python3 -c 'print("".join(chr(b ^ 0x5d) for b in b"\x35\x34\x1e\x09\x1b\x26"))'
hiCTF{
```

Nice, we can now use the same operation on the whole variable :
```bash
$ python3 -c 'print("".join(chr(b ^ 0x5d) for b in bytes.fromhex("35341e091b2639366d30022833316c3336026e2d2f6d3e6e2e2e02316c2e29023e2f6d2e2e023e356e3e36026a3e6e3c643b20")))'
hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}
```

Here is the flag : `hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}`