---
title: Ghost in the Wire
tags:
  - Forensics
---

# Ghost in the Wire

## Challenge Overview

Our network monitoring team detected anomalous ICMP traffic during a routine packet capture. Something is being exfiltrated through the wire — but the data blends in with normal network noise. Analyze the capture and extract the hidden message before the ghost disappears.

Files: [ghost-in-the-wire.zip](ghost-in-the-wire.zip)

SHA-256: `392084661bebf2a86f4194056436ddb2b78917577bc259cc07e1210f007c563c`

Flag Format: `hiCTF{}`

---

## Exploit

Inspecting the `.pcap` file revealed a series of ICMP packets carrying a distinct anomaly : each request contained a single extra byte of payload data. By extracting these individual bytes sequentially across all ICMP packets and concatenating them together, the hidden message was fully reassembled to reveal the flag :
```bash
tshark -r ghost_traffic.pcap -Y "icmp.type == 8" -T fields -e data | tr -d '\n' | xxd -r -p
AAAAAAAAAAAAAAAAping from server1hiCTF{1cmp_3xf1l_d3t3ct3d}health check ok  monitor alive 001
```

`tshark -r ghost_traffic.pcap -Y "icmp.type == 8" -T fields -e data` launches tshark, reads (`-r`) the target packet capture file with a filter (`-Y`) to isolate ICMP Echo Request and sets the output format to display specific packet fields (`-T fields`) and extracts solely the raw hex payload (`-e data`) from each packet. Then I used `tr -d '\n'` that delete all newline characters and finally I used `xxd -r -p` to pass the combined hex string to plain text mode.

Here is the flag : `hiCTF{1cmp_3xf1l_d3t3ct3d}`