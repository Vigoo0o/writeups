---
title: "Towel on the Sunbed"
category: "Web"
difficulty: "Medium"
date: "2026-08-03"
event: "TryHackMe Hacker Holidays"
tags: ["race-condition", "business-logic", "api-abuse", "burp-suite", "toctou"]
---

## Recon

Basic recon and directory enumeration turned up a site with sign-in and registration pages.

## Auth page

There's a JS function that makes the authentication request to an exposed API endpoint.

`auth.js`:

```js
function initAuthForm(formId, endpoint) {
  const form = document.getElementById(formId);
  const errorMsg = document.getElementById("error-msg");

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    errorMsg.classList.add("hidden");

    const data = Object.fromEntries(new FormData(form));
    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const json = await resp.json();
      if (!resp.ok) {
        errorMsg.textContent = json.error || "An error occurred.";
        errorMsg.classList.remove("hidden");
        return;
      }
      window.location.href = json.redirect || "/dashboard";
    } catch (err) {
      errorMsg.textContent = "Network error. Please try again.";
      errorMsg.classList.remove("hidden");
    }
  });
}
```

## Dashboard logic

`dashboard.js` loads the current user, their balance, a "claim" button with a cooldown timer, and a "vault" button that unlocks once the balance passes a threshold:

```js
const WHALE_THRESHOLD = 150;

let countdownTimer = null;

async function loadDashboard() {
  const resp = await fetch("/dashboard/api/me");
  if (resp.status === 401) {
    window.location.href = "/auth/login";
    return;
  }
  const data = await resp.json();

  document.getElementById("nav-username").textContent = data.username;
  document.getElementById("balance").textContent = data.balance.toLocaleString(
    undefined,
    { maximumFractionDigits: 2 },
  );

  const tierBadge = document.getElementById("tier-badge");
  tierBadge.textContent = data.tier;
  tierBadge.className = "tier-badge " + data.tier.toLowerCase();

  const tbody = document.querySelector("#prices-table tbody");
  tbody.innerHTML = "";
  for (const p of data.prices) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${p.symbol}</td><td class="price-val">$${p.price_usd.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>`;
    tbody.appendChild(tr);
  }

  const claimBtn = document.getElementById("claim-btn");
  const claimStatus = document.getElementById("claim-status");
  if (countdownTimer) clearInterval(countdownTimer);

  if (data.canClaim) {
    claimBtn.disabled = false;
    claimStatus.textContent = "Reward is available to claim now.";
  } else {
    claimBtn.disabled = true;
    let remaining = data.secondsUntilClaim;
    function updateCountdown() {
      const h = Math.floor(remaining / 3600);
      const m = Math.floor((remaining % 3600) / 60);
      const s = remaining % 60;
      claimStatus.textContent = `Next claim in: ${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
      if (remaining <= 0) {
        clearInterval(countdownTimer);
        claimBtn.disabled = false;
        claimStatus.textContent = "Reward is available to claim now.";
      }
      remaining--;
    }
    updateCountdown();
    countdownTimer = setInterval(updateCountdown, 1000);
  }

  const pct = Math.min(100, (data.balance / WHALE_THRESHOLD) * 100);
  document.getElementById("progress-fill").style.width = pct + "%";
  document.getElementById("progress-label").textContent =
    `${data.balance.toLocaleString()} / ${WHALE_THRESHOLD.toLocaleString()} PONZI`;

  const vaultBtn = document.getElementById("vault-btn");
  vaultBtn.disabled = data.balance < WHALE_THRESHOLD;
}

document.getElementById("claim-btn").addEventListener("click", async () => {
  const btn = document.getElementById("claim-btn");
  btn.disabled = true;
  const status = document.getElementById("claim-status");
  try {
    const resp = await fetch("/claim", { method: "POST" });
    const json = await resp.json();
    if (resp.ok) {
      status.textContent = `Claimed! +${json.reward} PONZI. PONZI price: $${json.priceSnapshot}`;
      await loadDashboard();
    } else {
      status.textContent = json.error || "Claim failed.";
      btn.disabled = false;
    }
  } catch (e) {
    status.textContent = "Network error.";
    btn.disabled = false;
  }
});

document.getElementById("vault-btn").addEventListener("click", async () => {
  const result = document.getElementById("vault-result");
  result.classList.add("hidden");
  try {
    const resp = await fetch("/vault");
    const json = await resp.json();
    if (resp.ok) {
      result.textContent = json.flag;
      result.classList.remove("hidden");
    } else {
      result.textContent = json.error || "Vault locked.";
      result.classList.remove("hidden");
    }
  } catch (e) {
    result.textContent = "Network error.";
    result.classList.remove("hidden");
  }
});

loadDashboard();
```

## Working the problem

Logging in via `curl` worked and returned a session cookie. Trying to "re-order" or fake the claim request just returned the usual API errors — the endpoint clearly checks server-side state, and the session cookie is required (the user ID alone isn't enough).

A NoSQL injection attempt on the login/claim flow didn't lead anywhere — this box wasn't about injection.

The next guess was time-based: could the server's clock be the weak point? That wasn't it either.

### The actual bug

The `/claim` endpoint:

- Sends a `POST` request.
- Grants a fixed reward (50 PONZI).
- Saves the updated balance — presumably at the _end_ of handling the request.

The question became: what happens if many claim requests are sent in the same second, before the first one finishes saving?

Sending 50 simultaneous requests returned 50 rewards. Sending a normal single repeat claim before the cooldown ended correctly returned a cooldown error, confirming the check exists — but it isn't atomic.

Sending roughly 30 concurrent requests in the same second returned a balance of **1550** PONZI — far past the 150-PONZI "whale" threshold needed to unlock the vault.

With the balance over the threshold, the `/vault` endpoint returned the flag.

### Root cause

This is a classic **race condition**: the claim handler reads the current balance, computes the new balance, and writes it back, but doesn't lock or serialize that read-modify-write sequence per user. Firing many requests at once lets several of them read the same "before" balance and all add their reward on top of it, instead of being queued one after another.

### Takeaway

Any "claim", "redeem", or "transfer" endpoint that reads a balance, changes it, and writes it back is a potential race-condition target. Testing it is simple: fire the same authenticated request many times in parallel (e.g. with a small script or a tool like `wrk`/`ffuf` in a loop) and see if the total reward exceeds what a single, sequential request should produce.
