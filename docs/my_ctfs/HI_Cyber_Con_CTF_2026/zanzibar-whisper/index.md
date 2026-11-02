---
title: Zanzibar Whisper
tags:
  - Steganography
---

# Zanzibar Whisper

## Challenge Overview

A mysterious image from the shores of Zanzibar has surfaced. Locals say it carries a hidden message — a whisper from the Spice Island. Can you uncover its secret?

Files: [zanzibar-whisper.zip](zanzibar-whisper.zip)

SHA-256: `48aedaaf1a363d859ceaece068354394edd6a8ff1ea7245af3fde395aa749a67`

Flag Format: `hiCTF{}`

---

## Exploit

Started by openning the image and testing basic commands like `binwalk` and `exiftools` without getting any results. I then tried steghide without any password :
```bash
steghide extract -sf zanzibar_whisper.jpg 
Enter passphrase: 
wrote extracted data to "zanzibar_flag2.txt".
```

In the file there is the flag : `hiCTF{sp1c3_1sl4nd_s3cr3ts}`