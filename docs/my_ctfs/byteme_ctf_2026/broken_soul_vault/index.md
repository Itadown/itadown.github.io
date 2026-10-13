---
title: Broken Soul Vault
tags: 
    - Forensics
---

# Broken Soul Vault

**Category Forensics**

## Challenge Description

The Soul Vault suffered metadata corruption during a recovery operation. Identify the valid recovered block and decode its contents.

**File Attachments :**

* [metadata.bin.txt](metadata.bin.txt)
* [vault.log](vault.log)


## Exploit

I opened metadata.bin.txt, it was clearly hex format so I copy paste on Ghex with ctrl+maj+v and select "Plain text (as hex string representing bytes)" to find the flag on the right:

`OWASP{br0k3n_s0ul_v4ult_r3c0v3r3d}`
