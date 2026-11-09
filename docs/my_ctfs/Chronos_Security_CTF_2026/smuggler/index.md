---
title: Smuggler
tags: 
    - Web
---

# Smuggler

Meridian Reporting is the internal reporting portal of the Meridian Continuity Directorate, a coalition partner in the Operation Dawn theatre. Desks file their returns here and most are listed for download, but one controlled packet is withheld from the dashboard and released only to a named distribution list.

Recover that packet. Start your own instance from this page and work only against the address it gives you.

Flag format: `CSCTF{...}`

---

First I looked at the web page and saw a file I couldn't download: Operation Dawn corridor logistics packet. Inspecting the HTML, I noticed that the downloadable files had links like /d/continuity-notice-11, using an ID rather than the full file name. Instead of trying to guess it, I used Burp Suite to intercept the response : 
```html
HTTP/1.1 200 OK
Server: meridian-reporting
Date: Sat, 07 Nov 2026 14:55:37 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 5411
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self' 'nonce-gH3uE8GA4r4W3ygti2ZlDw'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'
Cache-Control: no-store

[...]

<script nonce="gH3uE8GA4r4W3ygti2ZlDw">window.__CATALOG__ = [{"id": "corridor-status-wk41", "title": "Corridor status summary, week 41", "category": "Operations", "period": "Week 41, 2026", "updated": "2026-10-28 16:40 UTC", "access": "public"}, {"id": "corridor-status-wk40", "title": "Corridor status summary, week 40", "category": "Operations", "period": "Week 40, 2026", "updated": "2026-10-21 16:35 UTC", "access": "public"}, {"id": "corridor-status-wk39", "title": "Corridor status summary, week 39", "category": "Operations", "period": "Week 39, 2026", "updated": "2026-10-14 16:30 UTC", "access": "public"}, {"id": "fuel-stock-oct", "title": "Forward fuel stock reconciliation", "category": "Logistics", "period": "October 2026", "updated": "2026-10-27 09:12 UTC", "access": "public"}, {"id": "ammunition-return-q3", "title": "Ammunition holdings return, Q3", "category": "Logistics", "period": "Q3 2026", "updated": "2026-10-06 11:05 UTC", "access": "public"}, {"id": "medevac-readiness", "title": "Medical evacuation readiness return", "category": "Medical", "period": "October 2026", "updated": "2026-10-26 07:50 UTC", "access": "public"}, {"id": "casualty-regulating", "title": "Casualty regulating summary", "category": "Medical", "period": "Week 41, 2026", "updated": "2026-10-28 18:20 UTC", "access": "public"}, {"id": "comms-outage-log", "title": "Communications outage log", "category": "Signals", "period": "October 2026", "updated": "2026-10-27 22:05 UTC", "access": "public"}, {"id": "crypto-rekey-notice", "title": "Cryptographic rekey notice", "category": "Signals", "period": "Week 41, 2026", "updated": "2026-10-25 08:00 UTC", "access": "public"}, {"id": "liaison-roster-q3", "title": "Coalition liaison roster, Q3", "category": "Personnel", "period": "Q3 2026", "updated": "2026-10-02 13:40 UTC", "access": "public"}, {"id": "strength-return-oct", "title": "Unit strength return", "category": "Personnel", "period": "October 2026", "updated": "2026-10-20 10:15 UTC", "access": "public"}, {"id": "plant-serviceability", "title": "Plant and generator serviceability", "category": "Engineering", "period": "Week 40, 2026", "updated": "2026-10-19 15:25 UTC", "access": "public"}, {"id": "route-engineering", "title": "Route engineering state", "category": "Engineering", "period": "Week 41, 2026", "updated": "2026-10-28 14:10 UTC", "access": "public"}, {"id": "onboarding-brief", "title": "Reporting portal onboarding brief", "category": "General", "period": "Standing", "updated": "2026-09-30 09:00 UTC", "access": "public"}, {"id": "continuity-notice-11", "title": "Continuity standing notice 11", "category": "General", "period": "Standing", "updated": "2026-10-13 09:30 UTC", "access": "public"}, {"id": "ecb3b068cc47ab4b", "title": "Operation Dawn corridor logistics packet", "category": "Logistics", "period": "Movement window, 2026", "updated": "2026-10-29 06:15 UTC", "access": "controlled"}];</script>
<script nonce="gH3uE8GA4r4W3ygti2ZlDw" src="/static/js/dashboard.js?v=1359a45ec1"></script>
```

Here, there is a JavaScript array (`window.__CATALOG__`) containing all the hidden document IDs. This allowed me to retrieve the exact ID for the target file: `ecb3b068cc47ab4b`. By accessing `http://w01.ctf.chronos-security.ro:39060/d/ecb3b068cc47ab4b`, I downloaded a ZIP archive containing three files, including the one with the flag: `CSCTF{mGGHVHWC54bNEwxYpcokXB09}`.
