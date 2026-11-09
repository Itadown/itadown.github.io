---
title: Night Clerk
tags: 
    - Forensics
---

# Night Clerk

Ash Army proxies have been planting people inside coalition depots across the Operation Dawn theatre. One hostile clerk used a depot terminal to hide a coordination message before isolation, and only the retained stick image survives.

Recover the message from the image. Other exhibits it mentions are not provided and not needed, and you do not need to run anything in Office or mount the image. This is a constructed exercise, not a real incident. Attachment: `terminal.dd`, 8,388,608 bytes, SHA-256 `fb76b12579f7c1314df6e7556548a61c73c96157d95e77ba253c371c9d78bfb7`.

Submit the recovered `CSCTF{...}` value.

---

I started by analysing the file with `strings` to find that it is a NTFS partition with some data on it. I then tried to use `fls` to find some files :
```bash
$ fls -r -p terminal.dd 
r/r 4-128-1:	$AttrDef
r/r 8-128-2:	$BadClus
r/r 8-128-1:	$BadClus:$Bad
r/r 6-128-1:	$Bitmap
r/r 7-128-1:	$Boot
d/d 11-144-2:	$Extend
r/r 25-144-2:	$Extend/$ObjId:$O
r/r 24-144-3:	$Extend/$Quota:$O
r/r 24-144-2:	$Extend/$Quota:$Q
r/r 26-144-2:	$Extend/$Reparse:$R
r/r 2-128-1:	$LogFile
r/r 0-128-1:	$MFT
r/r 1-128-1:	$MFTMirr
r/r 9-128-2:	$Secure:$SDS
r/r 9-144-3:	$Secure:$SDH
r/r 9-144-4:	$Secure:$SII
r/r 10-128-1:	$UpCase
r/r 10-128-2:	$UpCase:$Info
r/r 3-128-3:	$Volume
r/r 64-128-2:	README.TXT
-/r * 65-128-2:	audit-0214.log
-/r * 66-128-2:	night_audit.docx
V/V 67:	$OrphanFiles
-/r * 16:	$OrphanFiles/OrphanFile-16
-/r * 17:	$OrphanFiles/OrphanFile-17
-/r * 18:	$OrphanFiles/OrphanFile-18
-/r * 19:	$OrphanFiles/OrphanFile-19
-/r * 20:	$OrphanFiles/OrphanFile-20
-/r * 21:	$OrphanFiles/OrphanFile-21
-/r * 22:	$OrphanFiles/OrphanFile-22
-/r * 23:	$OrphanFiles/OrphanFile-23
```

There I downloaded some file (with `icat`) to see what is in there and found out in `night_audit.docx` some interesting message, but first the `icat` command to extract it : 
```bash
icat terminal.dd 66 > night_audit.docx
```
And the content was :
```
Shift summary clean. Nothing unusual at the desk.7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44
```

Of course I saw that there is an hexadecimal so I went to [CyberChef](https://gchq.github.io/CyberChef/) where I use the following recipe : `From Hex -> XOR Brute Force`

I added a known plaintext string which was `CTF` to find the flag : `CSCTF{hid_skew_redline}`