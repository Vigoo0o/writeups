---
title: "CryptoCabana — Day #9"
category: "Cloud"
difficulty: "Medium"
date: "2026-08-04"
event: "TryHackMe Hacker Holidays"
tags: ["azure", "cloud-security", "sas-token", "key-vault", "service-principal"]
---

## 1. What is Azure?

Azure is Microsoft's cloud platform. Instead of buying physical servers, you "rent" Microsoft's infrastructure over the internet:

- **Virtual machines (VMs)** — rented Windows/Linux servers.
- **Storage** — file/object storage (blobs, containers).
- **Databases, networking, identity** (users, permissions), **Key Vaults** (secret storage), etc.

Everything is managed through APIs and a web console. For a pentester, Azure matters because a lot of companies host apps there — and misconfigurations, like the leaked SAS token in this challenge, become attack paths.

## 2. The Azure Portal, briefly

| Component                | What it is                                              |
| ------------------------ | ------------------------------------------------------- |
| Subscription             | Your billing/access boundary — the sandbox for this lab |
| Resource groups          | Folders that group related resources                    |
| Virtual machines         | Servers you can create, start, stop, SSH/RDP into       |
| Storage accounts / blobs | Where files are stored (what this challenge abuses)     |
| Key Vault                | Where secrets, keys, and certificates are kept          |
| Cloud Shell              | The built-in browser terminal                           |
| Entra ID (Azure AD)      | Users, roles, and permissions                           |

Azure Cloud Shell is not a server you own — it's a temporary container Microsoft spins up for the session, with the Azure CLI pre-installed. It's ephemeral: anything installed is gone once the session ends unless a storage account is attached.

Quick starter commands:

```bash
az account show
az resource list
az storage account list
az keyvault list
```

All of these returned empty for the sandbox subscription — which is the point of the room.

## 3. Control plane vs. data plane

This is the key concept for this room:

- **Control plane** — like a hotel front desk. `az resource list` asks "what rooms exist?", and the answer depends on your permission badge (RBAC roles).
- **Data plane** — the actual rooms. If someone hands you a key card (a token, a key, a SAS token), you can open that room and read everything inside, even if the front desk never told you the room exists.

The portal lists were empty because, from this identity, there's no control-plane view of the subscription. But the lab's resources definitely exist — so the real question is: where's the key card? In these rooms, the answer is almost always inside the public-facing web app.

## 4. The public site

`https://cryptocabanaf5scjagc.z13.web.core.windows.net/`

This site is **not** inside the visible subscription — and that's the whole lesson. It's hosted on Azure Storage as a static website: just files in a container with public read access. The attack surface was never the portal; it's the public web app itself.

Reading the URL:

```
https://cryptocabanaf5scjagc.z13.web.core.windows.net/
       └────────┬─────────┘ └┬┘ └─────────┬─────────┘
        storage account    stamp   static-site domain
```

- `cryptocabanaf5scjagc` — the globally unique storage account name.
- `z13` — the storage "stamp" (a numbered cluster in an Azure region).
- `web.core.windows.net` — the special domain for static website hosting on blob storage.

Two endpoints, one account:

```
https://cryptocabanaf5scjagc.z13.web.core.windows.net/   ← static website (public $web container)
https://cryptocabanaf5scjagc.blob.core.windows.net/      ← raw storage, front door to ALL containers
```

A static site is literally just files in a container — no server, no database, no hidden backend logic. Everything the developers wrote, including mistakes, sits in plain text.

## 5. The app

CryptoCabana is a "kiosk" web app where guests can supposedly back up their crypto seed phrases. A resort guest's wallet was emptied by a transaction that was validly signed — just not by him, meaning someone else had his private key. He'd backed his seed phrase up into the kiosk's vault, whose slogan promised "Backed up. Sleep easy." The objective: find out what the kiosk is quietly trusting to reach into storage on its own, and see how much further that trust extends.

`app.js`:

```js
const STORAGE_ACCOUNT = "cryptocabanaf5scjagc";
const BACKUPS_CONTAINER = "backups";
const BACKUP_SAS =
  "?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=ZAo05W8KXdSLM9afYCNGogNRV2N5a6aB4dQI3LXz%2Fh0%3D";

function backupPhrase() {
  const phrase = document.getElementById("phrase").value.trim();
  const status = document.getElementById("status");
  if (!phrase) {
    status.textContent = "Enter a phrase first.";
    return;
  }

  const blobName = "backup-" + Date.now() + ".txt";
  const url =
    "https://" +
    STORAGE_ACCOUNT +
    ".blob.core.windows.net/" +
    BACKUPS_CONTAINER +
    "/" +
    blobName +
    "?" +
    BACKUP_SAS;

  fetch(url, {
    method: "PUT",
    headers: { "x-ms-blob-type": "BlockBlob" },
    body: phrase,
  })
    .then((res) => {
      status.textContent = res.ok
        ? "Backed up. Sleep easy."
        : "Backup failed (" + res.status + ").";
    })
    .catch(() => {
      status.textContent = "Backup failed — network error.";
    });
}
```

- `STORAGE_ACCOUNT` — the storage account holding the kiosk's files.
- `BACKUPS_CONTAINER` — where seed-phrase backups are meant to live.
- `BACKUP_SAS` — a bearer credential. It's a data-plane key, so it needs no portal login at all.

## 6. Reading the SAS token

```
sv=2022-11-02  ss=b  srt=sco  sp=rl  se=2099-12-31  st=2024-01-01  spr=https  sig=...
```

| Param     | Value       | Meaning                                           |
| --------- | ----------- | ------------------------------------------------- |
| `sv`      | 2022-11-02  | API version the signature is bound to             |
| `ss`      | b           | Signed services: blob storage only                |
| `srt`     | sco         | Signed resource types: service, container, object |
| `sp`      | rl          | Permissions: read + list                          |
| `st`/`se` | 2024 → 2099 | Valid for ~75 years — effectively never expires   |
| `spr`     | https       | HTTPS only                                        |
| `sig`     | ...         | HMAC signature proving Microsoft issued it        |

The `srt=sco` value is the giveaway: this SAS can operate at the **service level of the entire storage account**, not just inside `backups`. A container-only SAS would use `sr=c` instead. The developer likely intended access to only `backups` — in reality the token can list every container in the account and read every blob in them.

Also worth noting: the code `PUT`s a backup, but `sp=rl` has no write permission, so uploads through the app actually fail with 403 — the kiosk's own backup feature is broken, meaning the victim's real backup must have landed somewhere else.

## 7. Using the token against the account

```bash
export AZURE_STORAGE_ACCOUNT="cryptocabanaf5scjagc"
export AZURE_STORAGE_SAS_TOKEN="sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=ZAo05W8KXdSLM9afYCNGogNRV2N5a6aB4dQI3LXz%2Fh0%3D"
```

Every `az storage` command now authenticates with the token — no portal login needed. Listing containers revealed:

| Container | What it is                                                                            |
| --------- | ------------------------------------------------------------------------------------- |
| `$web`    | The static site files — the public kiosk already read via the browser                 |
| `backups` | Where the kiosk _intends_ to store backups (empty, since writes fail)                 |
| `vault`   | Not part of the kiosk's design at all — this is the "further" the briefing pointed to |

Reading a blob inside `vault` returned:

```json
{
  "client_id": "dbcf2923-e4eb-4b72-a0a4-688aa1185cf5",
  "client_secret": "UBX8Q~xM6vawWZ5u2C-VhLlsB2Cx2dAuxcrAlbRg",
  "key_vault_name": "ccabana-kv-f5scjagc",
  "key_vault_uri": "https://ccabana-kv-f5scjagc.vault.azure.net/",
  "note": "CryptoCabana backup automation account. Rotate this if it ever leaves the vault. -- IT",
  "tenant_id": "8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c"
}
```

## 8. Service principal → Key Vault

This is a **service principal (SP)** — an identity Azure creates for applications instead of humans. Think of it as a robot employee: it logs in with a `client_id` (username) and `client_secret` (password) instead of an email and password, and authenticates via API rather than a portal login.

The attack chain so far:

| Step | What happened                             | Concept                         |
| ---- | ----------------------------------------- | ------------------------------- |
| 1    | Read JS → got SAS token                   | Data-plane trust (storage)      |
| 2    | Listed containers → found `vault`         | Scope creep (`srt=sco`)         |
| 3    | Read blob in `vault` → got SP credentials | Credential discovery            |
| 4    | Use SP to reach Key Vault                 | Identity-plane trust (Entra ID) |

Starting with no cloud access at all, this ends with a credential that can act as a legitimate Azure identity — lateral movement from the storage plane into the identity plane.

### Azure Key Vault

A managed vault for secrets — API keys, passwords, certificates. Like storage, it has its own data plane: access is granted to identities via policies or RBAC, and secrets are read with `az keyvault secret ...` commands. You can't see a vault's contents just by listing subscriptions — you need identity + permission, exactly like storage needed the SAS token.

### Logging in as the robot

```bash
az login --service-principal \
  --username "dbcf2923-e4eb-4b72-a0a4-688aa1185cf5" \
  --password "UBX8Q~xM6vawWZ5u2C-VhLlsB2Cx2dAuxcrAlbRg" \
  --tenant "8f8c5f8e-42d3-4ceb-97ad-241bbf446d6c"

az account show   # confirm the session is now the robot identity
```

Listing and reading secrets:

```bash
az keyvault secret list --vault-name ccabana-kv-f5scjagc -o table
az keyvault secret show --vault-name ccabana-kv-f5scjagc --name <secret-name>
```

The first part of the flag came back directly: `THM{n0t_ur`. A second secret showed as rotated / redirected — the current value wasn't the one needed. The hint was that an older value should still be recoverable.

### Recovering an older secret version

```bash
az keyvault secret list-versions \
  --vault-name ccabana-kv-f5scjagc \
  --name key-shard-2 \
  --query "[].id" \
  -o table
```

This returned two versions. Reading the older one:

```bash
az keyvault secret show \
  --id <VERSION_URL> \
  -o table
```

That produced the final part of the flag: `ur_c01ns!}`.

## 9. Flag

`THM{n0t_ur_c01ns!}`
