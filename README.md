# 🪙 Tokenmint

[![PyPI version](https://img.shields.io/pypi/v/tokenmint.svg)](https://pypi.org/project/tokenmint/)
[![Python versions](https://img.shields.io/pypi/pyversions/tokenmint.svg)](https://pypi.org/project/tokenmint/)
[![License](https://img.shields.io/pypi/l/tokenmint.svg)](https://github.com/shaileshpandit141/tokenmint/blob/main/LICENSE)

**Tokenmint** is a modern Python library for issuing and verifying **limited-time, scoped, and replay-protected tokens**.
Built for 2025 and beyond, it provides a **production-grade token system** with features like **key rotation, purpose scoping, Redis-backed replay prevention, and secure Ed25519 signatures**.

## ✨ Features

* 🔑 **Key rotation** with `kid` headers for zero-downtime upgrades
* ⏳ **Limited-time tokens** (short-lived, scoped, expiring)
* 🛡 **Replay protection** using Redis-backed JTI tracking
* 🎯 **Strict purpose scoping** (e.g., `email-verify`, `password-reset`)
* 🖋 **EdDSA (Ed25519)** signatures for modern cryptographic security
* 🏗 Production-ready: structured errors, leeway for clock skew, revocation support
* ⚡ Works with Django, FastAPI, Flask, or standalone services

## 📦 Installation

You can install **Tokenmint** via **pip** or **uv**:

* **Using uv**

```bash
uv add tokenmint
```

* **Using pip**

```bash
pip install tokenmint
```

## 🚀 Quick Start

```python
from datetime import timedelta
from tokenmint.settings import Settings
from tokenmint.services import TokenMint

# Define token settings
settings = Settings(
    issuer="myapp.io",
    audience="myapp.web",
    purpose="email-verify",
    expiry_duration=timedelta(minutes=15),
)

# Create token mint (auto-loads keys from environment, uses Redis for replay prevention)
mint = TokenMint(settings)

# Generate a token
token = mint.generate_token(
    subject="20",
    extra_claims={"email": "alice@example.com"},
)

print("Issued token:", token)

# Validate a token
claims = mint.validate_token(token)
print("Decoded claims:", claims)
```

## 🔐 Key Management

tokenmint uses **Ed25519 key pairs** with support for **key rotation**.
Keys are loaded from environment variables:

```bash
export TOKEN_ACTIVE_KEY_ID="2025-08-rot-1"
export TOKEN_PRIVATE_KEY_2025-08-rot-1="$(cat ed25519-private.pem)"
```

* Rotate by adding a new private key (`TOKEN_PRIVATE_KEY_<new_id>`)
* Update `TOKEN_ACTIVE_KEY_ID` to the new key id
* Old tokens remain valid until expiry since their public keys are still available

## 📖 Detailed Use Cases

tokenmint is designed to fit common security-sensitive flows. Below are example implementations.

### 1. 🔑 **Email Verification**

Send a time-limited verification link when a user signs up:

```python
from datetime import timedelta
from tokenmint.settings import Settings
from tokenmint.services import TokenMint

settings = Settings(
    issuer="myapp.io",
    audience="myapp.web",
    purpose="email-verify",
    expiry_duration=timedelta(minutes=10),
)

mint = TokenMint(settings)

# Issue a token for user
token = mint.generate_token(
    subject="20",
    extra_claims={"email": "alice@example.com"},
)

# Send via email link
verification_url = f"https://myapp.io/verify-email?token={token}"
print("Verification URL:", verification_url)

# Later, when user clicks the link
claims = mint.validate_token(token)
print("Verified email:", claims["email"])
```

✔ Prevents token replay
✔ Short lifetime
✔ Scoped to `"email-verify"`

### 2. 🔒 **Password Reset**

```python
settings = Settings(
    issuer="myapp.io",
    audience="myapp.web",
    purpose="password-reset",
    expiry_duration=timedelta(minutes=5),
)

mint = TokenMint(settings)

# Issue reset token
reset_token = mint.generate_token(subject="20")

# User submits new password with token
claims = mint.validate_token(reset_token)

# Force revoke once used
mint.revoke_token(reset_token)
```

✔ Ensures token can’t be reused
✔ Scoped only for password reset flow

### 3. 📩 **Magic Login Links**

No passwords — just a one-time-use link:

```python
settings = Settings(
    issuer="myapp.io",
    audience="myapp.web",
    purpose="magic-login",
    expiry_duration=timedelta(minutes=2),
)

mint = TokenMint(settings)

login_token = mint.generate_token(subject="20")

# When clicked
claims = mint.validate_token(login_token)
print("User logged in:", claims["sub"])
```

✔ Very short-lived
✔ One-time login enforcement via replay cache

### 4. ⚙️ **Scoped API Access**

Issue short-lived tokens for microservice-to-microservice communication:

```python
settings = Settings(
    issuer="auth.myapp.io",
    audience="payments.myapp.io",
    purpose="service-access",
    expiry_duration=timedelta(minutes=1),
)

mint = TokenMint(settings)

api_token = mint.generate_token(subject="user@gmail.com")

# Receiving service validates
claims = mint.validate_token(api_token)
print("Authorized service:", claims["sub"])
```

✔ Audience restriction
✔ Purpose scoping ensures the token is useless elsewhere

### 5. 🎟 **One-Time Session Tokens**

Great for **single-use sensitive operations** (like transferring funds):

```python
settings = Settings(
    issuer="myapp.io",
    audience="myapp.api",
    purpose="txn-approval",
    expiry_duration=timedelta(minutes=3),
    prevent_replay=True,
)

mint = TokenMint(settings)

txn_token = mint.generate_token(
    subject="20",
    extra_claims={"amount": "100.00", "currency": "USD"},
)

# Validate (once only)
claims = mint.validate_token(txn_token)

# Reuse attempt → raises InvalidTokenError
mint.validate_token(txn_token)
```

### 6. 🏗 One-Time Payment Approval Token

**Scenario:**
Your app allows users to approve payments securely. Each token must:

* Be valid only for a single payment request
* Expire quickly (e.g., 3 minutes)
* Include extra claims like `amount` and `currency`
* Prevent token replay using Redis
* Support production-grade key rotation

#### Environment Setup

```bash
export TOKEN_ACTIVE_KEY_ID="2025-08-rot-1"
export TOKEN_PRIVATE_KEY_2025-08-rot-1="$(cat prod-ed25519-rot1.pem)"
export TOKEN_PRIVATE_KEY_2025-05-rot-0="$(cat prod-ed25519-rot0.pem)"
export REDIS_URL="redis://prod-redis-server:6379/3"
```

#### Define Token Settings

```python
from datetime import timedelta
from tokenmint.settings import Settings

settings = Settings(
    issuer="payments.myapp.io",
    audience="payments.api",
    purpose="payment-approval",     # scoped to payment approval
    expiry_duration=timedelta(minutes=3),
    clock_skew_leeway=5,            # allow 5 seconds for clock differences
    prevent_replay=True,            # single-use enforcement
)
```

#### Configure Redis Replay Cache

```python
from tokenmint.cache import ReplayCache
import os

redis_url = os.getenv("REDIS_URL")
replay_cache = ReplayCache(redis_url=redis_url, key_prefix="prod:payment:jti:")
```

✅ This isolates payment tokens in Redis to prevent collisions with other token types.

#### Initialize TokenMint

```python
from tokenmint.services import TokenMint

mint = TokenMint(
    settings=settings,
    replay_cache=replay_cache,
)
```

#### Generate Payment Approval Token

```python
payment_token = mint.generate_token(
    subject="20",
    extra_claims={"amount": "250.00", "currency": "USD", "payment_id": "txn_1001"}
)

print("Send this token to the frontend for approval:", payment_token)
```

✅ Includes `amount`, `currency`, and `payment_id` claims, ensuring the token is **specific to one payment**.

#### Validate Token During Approval

```python
from tokenmint.exceptions import InvalidTokenError

try:
    claims = mint.validate_token(payment_token)
    print("Payment approved for:", claims["sub"])
    print("Amount:", claims["amount"], claims["currency"])
except InvalidTokenError as e:
    print("Invalid or reused token:", str(e))
```

✅ Checks signature, issuer, audience, expiry, and **prevents reuse**.

#### Revoke Token Explicitly (Optional)

```python
mint.revoke_token(payment_token)
```

✅ Ensures a token can never be reused even before natural expiry.

### Production Notes

* Use **dedicated Redis DBs or key prefixes** for different token types (`prod:payment:jti:`).
* **Rotate keys** safely with old keys kept in `KeyStore` for verification of existing tokens.
* **ReplayCache TTL** matches token expiry, no manual cleanup needed.
* Purpose scoping (`payment-approval`) prevents tokens from being misused for other actions.

## 🔑 Build Any Tokenized Flow with Replay Protection

tokenmint enforces **true single-use tokens** with Redis-backed replay prevention.  
With these building blocks, you can implement **any tokenized flow** - from user onboarding to secure inter-service communication.

## 🤝 Contributing

Contributions are welcome! Please open an issue or PR for any improvements.

## 📜 License

MIT License — See [LICENSE](LICENSE).

## 👤 Author

**Shailesh Pandit**  

* 🌐 Website: [https://github.com/shaileshpandit141](https://github.com/shaileshpandit141)  
* 🐙 GitHub: [https://github.com/shaileshpandit141](https://github.com/shaileshpandit141)  
* 💼 LinkedIn: [https://www.linkedin.com/in/shaileshpandit141](https://www.linkedin.com/in/shaileshpandit141)  
* ✉️ Email: [shaileshpandit141@gmail.com](mailto:shaileshpandit141@gmail.com)
