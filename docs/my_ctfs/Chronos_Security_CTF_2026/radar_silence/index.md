---
title: Radar Silence
tags: 
    - Network
---

# Radar Silence

BRIEFING

RDR37 (`192.0.2.37`) carries the air-surveillance radar link of an Operation Dawn ally whose picture feeds the coalition's shared air surveillance; OPS40 (`192.0.2.40`) logs operations. Before a scheduled cutover, analysts marked RDR37 for a suspected bearer-token leak.

This PCAPNG is an isolated-lab replay, not a production capture. Determine whether a bearer token left RDR37 and recover it for reissue.

Submit `CSCTF{<source>_rotation_<token>}` using the lower-case station ID and a 32-character lower-case hex token.

File : [radar-silence.pcapng](./radar-silence.pcapng)

---

By looking at the capture, we can spot a suspicious DNS exfiltration pattern. Multiple UDP packets are sent from source IP `192.0.2.37` to subdomains following the pattern `<payload>.<index>.update.svc-telemetry.example`.

Notice the index format: it changes every time from `00` to `03`, indicating a chunked data stream that needs to be reassembled in chronological order.

Extracting the requests:
* `rtamrzg5sgiyz.02.update.svc-telemetry.example`
* `miytaojxmy3gk.00.update.svc-telemetry.example`
* `tgmztknjqhfta.03.update.svc-telemetry.example`
* `ojxg4ydcnldmf.01.update.svc-telemetry.example`

Sorting them from `00` to `03` gives us the continuous payload:
* `miytaojxmy3gkojxg4ydcnldmfrtamrzg5sgiyztgmztknjqhfta`

DNS resolvers are case-insensitive (`A.COM` is identical to `a.com`). Standard Base64 requires case sensitivity (`A` / `a`), making it unreliable for DNS tunneling without custom character mapping.

Inspecting the encoded payload reveals only characters from `a-z` and numbers `2-7` (notice digits like `3`, `4`, `5`). The exclusion of `0`, `1`, `8`, and `9` is the classic RFC 4648 Base32 alphabet signature designed specifically to avoid character ambiguity.

The briefing identifies `192.0.2.37` as `rdr37`, decoding the 52-char Base32 string gives us : `b1097f6e977015cac0297ddc3335509f`.

So the flag is : `CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`
