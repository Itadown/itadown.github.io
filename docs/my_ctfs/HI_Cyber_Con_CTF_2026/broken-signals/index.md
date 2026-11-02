---
title: Broken Signals
tags: 
    - Forensics
---

# Broken Signals

## Challenge Description

Our signals intelligence team intercepted a file during a routine sweep, but it appears corrupted. The file cannot be opened by any standard application. Something is wrong with the file itself — can you repair it and recover the hidden message?

Files: [broken-signals.zip](broken-signals.zip)

SHA-256: `47517fa29db01823c9416f0b285f069e2022d63c956d87fb995c1b97a9ea34f5`

Flag Format: `hiCTF{}`

--- 

## Exploit

Running `strings` on the target file revealed an `IHDR` chunk header, pointing to a `PNG` image structure. Inspecting the file in GHex showed that the image was unreadable due to a corrupted file header where the standard magic bytes had been replaced with null bytes (`00 00 00 00`). After restoring the missing `PNG` header (`89 50 4E 47 0D 0A 1A 0A`) at the start of the file, the image loaded cleanly and revealed the flag: `hiCTF{h34d3r_r3p41r_m4st3r}`.