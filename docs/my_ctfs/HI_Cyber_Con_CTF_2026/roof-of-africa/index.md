---
title: Root of Africa
tags:
  - Steganography
---

# Root of Africa

## Challenge Overview

They say Africa's highest peak holds ancient secrets in its frozen glaciers. A photograph has been intercepted — but its true meaning is locked away, protected by the mountain's most famous number.

Can you reach the summit and uncover what lies hidden?

Files: [roof-of-africa.zip](roof-of-africa.zip)

SHA-256: `137a5a7ec2a314e1027a7a279d33e45cd0a95256f63b35cca2d3fb233c3209ed`

Flag Format: `hiCTF{}`

---

## Exploit

Initial visual and metadata analysis via StegOnline yielded no results. Referring back to the hint about "the mountain's most famous number," I identified Mount Kilimanjaro and used its height (5895) as the passphrase for `steghide` :
```bash
steghide extract -sf roof_of_africa.jpg
Enter passphrase: 
wrote extracted data to "roof_flag_v2.txt".
```

Here is the flag obtained in `root_flag_v2.txt` : `hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}`