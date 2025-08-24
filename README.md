# 🪙 Authmint

**Authmint** is a modern Python library for issuing and verifying **limited-time, scoped, and replay-protected tokens**.
Built for 2025 and beyond, it provides a **production-grade token system** with features like **key rotation, purpose scoping, Redis-backed replay prevention, and secure Ed25519 signatures**.

## ✨ Features

* 🔑 **Key rotation** with `kid` headers for zero-downtime upgrades.
* ⏳ **Limited-time tokens** (short-lived, scoped, expiring).
* 🛡 **Replay protection** using Redis-backed JTI tracking.
* 🎯 **Strict purpose scoping** (e.g., `email-verify`, `password-reset`).
* 🖋 **EdDSA (Ed25519)** signatures for modern cryptographic security.
* 🏗 Production-ready: structured errors, leeway for clock skew, revocation support.
* ⚡ Works with Django, FastAPI, Flask, or standalone services.

### 📦 Installation

```bash
pip install authmint
```

### 🚀 Quick Start

```python
from datetime import timedelta
from authmint import TokenService, TokenConfig, load_key_manager_from_env

# Bootstrap from env (TOKEN_CURRENT_KID, TOKEN_KEYS_* must be set)
km = load_key_manager_from_env()
svc = TokenService(km)

cfg = TokenConfig(
    issuer="myapp.io",
    audience="myapp.web",
    purpose="email-verify",
    ttl=timedelta(minutes=15),
)

# Issue a token
token = svc.issue(
    sub="user:42",
    config=cfg,
    extra_claims={"email": "alice@example.com"},
)

# Verify a token
claims = svc.verify(token, expected=cfg)
print(claims)
```

### 🔐 Key Management

Set keys as environment variables:

```bash
export TOKEN_CURRENT_KID="2025-08-rot-1"
export TOKEN_KEYS_2025-08-rot-1="$(cat ed25519-private.pem)"
```

Rotate keys safely by adding new ones and switching `TOKEN_CURRENT_KID`.

### 📖 Use Cases

* ✅ Email verification links
* ✅ Password reset flows
* ✅ Magic login links
* ✅ Scoped API access with TTL
* ✅ One-time-use session tokens

### 🛠 Roadmap

* [ ] PASETO v4 support
* [ ] Optional JWE (encrypted token)
* [ ] First-class FastAPI / Django integration helpers
