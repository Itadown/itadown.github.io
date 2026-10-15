---
title: Mission 3: Forensics, Reverse Engineering
tags: 
    - Forensics
    - Reverse Engineering
---

# Mission 3: Forensics, Reverse Engineering

## Challenge Overview

The Quantumcore organization experienced a compromise following an employee downloading a suspicious file. Analysts recovered a compromised Linux Virtual Machine (OVA) image along with a packet capture file (`capture.pcap`). The objective is to identify the initial access vector, analyze the installed malware, reverse-engineer its exfiltration mechanism, and recover the compromised data from the network traffic.

---

## 1. Initial System Forensics & Access

### VM Access & Privilege Escalation via GRUB
During initial access, standard authentication failed. Access was recovered by booting into single-user mode via GRUB and launching an unauthenticated root shell.

### User Account & Log Analysis
* **`johndoe`**: Primary user account with sudo privileges. Its `.bash_history` file was wiped prior to malware execution, with a last modification timestamp recorded on **March 25 at 04:51**.
* **`tempuser`**: Secondary account created on **March 25 at 09:04**, indicating potential attacker activity around this timeframe.

### Filesystem Timeline Investigation
Investigating root-level directories revealed a cluster of modifications occurring on **March 25 at 09:04**:

* `/root/.sudo_as_admin_successful`: Touched at 09:04 (empty file).
* `/root/.lesshst`: Modified at 09:03.
* `/opt`: Contained 10 hidden files and 40 subdirectories created at 09:04.
* **Suspicious Directory**: `/opt/fJQsJUNS/` containing a hidden executable file named `.sys`.

---

## 2. Network Capture Analysis & Staging Script Discovery

### Extracting HTTP Objects via Wireshark

Opening `capture.pcap` in Wireshark, the first logical step was to check for downloaded files using the built-in HTTP object exporter:

* **Action:** Navigate to `File` -> `Export Objects` -> `HTTP`.
* **Discovered Artifact:** A shell script named [install_nptdate.sh](install_nptdate.sh)  was identified and saved locally for analysis.

### Analyzing the file

Examining the contents of [install_nptdate.sh](install_nptdate.sh) revealed the staging configuration and variables used by the attacker:

* `__DL`: `"http://vastation.null:8080/ntpdate_util.cpython-37.pyc"`
* `__DLL`: `"http://vastation.null:8080/readme.md"`
* `__C`: `'@reboot "root PYTHONPATH=""'`
* `__V`: `"python3.7"`

The script drops a persistent cron job into `/etc/cron.d/.ntpdate_sync` with the following command:

```cron
@reboot root PYTHONPATH=/home/johndoe/.local/lib/python3.7/site-packages python3.7 /opt/fJQsJUNS/.sys &
```

This confirmed that the payload downloaded from `vastation.null` was stored locally at `/opt/fJQsJUNS/.sys` and executed at boot.

---

## 3. Malware Inspection & Decompilation (`/opt/fJQsJUNS/.sys`)

### Static String Inspection

With the path `/opt/fJQsJUNS/.sys` identified, inspecting the file on the filesystem revealed it was a compiled Python binary disguised as a `.sys` file.

Running `strings` with a filter for cryptographic keywords yielded crucial information:

```bash
strings /opt/fJQsJUNS/.sys | grep -iE 'http|base64|open|send|socket|AES|post|get|upload|write|key|CBC|ECB|CTR|GCM'
```

**Raw Output Obtained:**
```text
AESZ e8f93d68b1c2d4e9f7a36b5c8d0f1e2aZ 1f2d3c4b5a69788766554433221100ffZ 37e0f8f92c71f1c3f047f43c13725ef1c
base64
MODE_CBC
open
targets
```

**Extracted Credentials & Keying Material:**
* **Encryption Mode:** `MODE_CBC`
* **AES Key** (`__k`)**:** `e8f93d68b1c2d4e9f7a36b5c8d0f1e2a`
* **Initialization Vector** (`__v`)**:** `1f2d3c4b5a69788766554433221100ff`
* **Encrypted C2 Domain** (`__d`)**:** `37e0f8f92c71f1c3f047f43c13725ef1`

### Decompiling the Python Payload

To analyze the full execution logic, `.sys` was renamed to `.pyc` and decompiled using `uncompyle6`:

```bash
mv /opt/fJQsJUNS/.sys sys.pyc
uncompyle6 sys.pyc > src.py
```

### Decompiled Code Logic

Analyzing [src.py](src.py) confirmed that:
1. Anti-VM and anti-AV checks are performed prior to execution.
2. Sensitive targets (such as `/root/.secret` and SSH keys) are targeted.
3. Data is encrypted using **AES-128-CBC** with the extracted key and IV.
4. Exfiltration occurs via **ICMP Echo Request (`ping`)** packets, embedding encrypted chunks inside the ICMP payload field.

---

## 4. ICMP Payload Extraction & Decryption

### Extracting ICMP Data with `tshark`

Focusing on ICMP traffic originating from the infected host IP `192.168.1.5` in Wireshark, payload data was clearly visible inside ping requests. However, inspecting the raw data revealed duplication and extra padding appended to each packet.

Only the first **16 bytes (32 hex characters)** contained the actual AES encrypted block. To extract just the relevant ciphertext chunks, `tshark` was combined with `awk`:

```bash
tshark -r capture.pcap -Y "ip.src == 192.168.1.5 and icmp" -T fields -e data | awk '{print substr($0, 1, 32)}' > hex_chunks.txt
```

### Decrypting the Exfiltrated Data

Rather than writing a standalone script from scratch, the malware's own `__x()` decryption routine inside `nightshade.py` was reused by modifying its `__main()` function to iterate over `hex_chunks.txt` and print the decrypted output:

```python
# uncompyle6 version 3.9.2
# Python bytecode version base 3.7.0 (3394)
# Embedded file name: nightshade.py
# Compiled at: 2025-03-24 16:04:51

import os, subprocess, psutil, base64
from Crypto.Cipher import AES

__k = bytes.fromhex("e8f93d68b1c2d4e9f7a36b5c8d0f1e2a")
__v = bytes.fromhex("1f2d3c4b5a69788766554433221100ff")
__d = "37e0f8f92c71f1c3f047f43c13725ef1"

def __b64d(s):
    return base64.b64decode(s.encode()).decode()

def __p(x):
    return x + bytes([16 - len(x) % 16]) * (16 - len(x) % 16)

def __u(x):
    return x[:-x[-1]]

def __x(h):
    c = AES.new(__k, AES.MODE_CBC, __v)
    return __u(c.decrypt(bytes.fromhex(h))).decode()

def __y(s):
    c = AES.new(__k, AES.MODE_CBC, __v)
    return c.encrypt(__p(s.encode())).hex()

def __main():
    # Read extracted ICMP 16-byte hex chunks
    with open('./hex_chunks.txt', 'r') as file:
        lines = file.readlines()

    # Process each 16-byte chunk through the malware's decryption function __x()
    for line in lines:
        if line.strip():
            try:
                decrypted = __x(line.strip())
                print(decrypted, end="")
            except Exception as e:
                print(f"Error decrypting line: {e}")

if __name__ == "__main__":
    __main()
```

---

## 5. Flag Recovery

Running the decryption script against the extracted ICMP chunks successfully recovered the exfiltrated flag:

`RM{986b8674b18e7f3c36b24cf8c8195b36bba01d61}`
