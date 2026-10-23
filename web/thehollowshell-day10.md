---
title: "The Hollow Shell"
category: "Web"
difficulty: "Medium"
date: "2026-08-05"
event: "TryHackMe Hacker Holidays"
tags:
  [
    "zip-slip",
    "arbitrary-file-write",
    "path-traversal",
    "remote-code-execution",
    "python",
  ]
---

## Recon

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
5000/tcp open  upnp?
```

Port 5000 was reported as `upnp?` by Nmap's version scan, which is usually a false positive — worth a manual look with a browser or `curl` rather than trusting the service guess.

## Credentials found

- **user:** `concierge`
- **pass:** `StayNoticed2024!`

_Write-up in progress — exploitation steps and flag to follow._
