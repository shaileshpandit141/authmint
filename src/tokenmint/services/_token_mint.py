import secrets
import time
from datetime import datetime, timedelta, timezone
from os import environ
from typing import Any

from jwt import InvalidTokenError, decode, get_unverified_header

from tokenmint.cache import ReplayCache
from tokenmint.settings import Settings
from tokenmint.stores import KeyStore
from tokenmint.schema import ClaimDict


class TokenMint:
    """
    High-level API to generate, validate, and revoke limited-time tokens with strict scoping.
    """

    def __init__(
        self,
        settings: Settings,
        replay_cache: ReplayCache | None = None,
    ) -> None:
        self.settings = settings
        self.key_store = self._load_environ_tokens()
        self.replay_cache = replay_cache or ReplayCache(
            redis_url="redis://localhost:6379/0",
        )

    @staticmethod
    def _load_environ_tokens() -> KeyStore:
        """
        Example loader:
        - TOKEN_ACTIVE_KEY_ID = "v1"
        - TOKEN_PRIVATE_KEY_v1 = "PEM-encoded Ed25519 private key"
        - TOKEN_PRIVATE_KEY_v0 = "previous key"
        """
        prefix = "TOKEN_PRIVATE_KEY_"
        token_private_keys: dict[str, str] = {}
        for key, value in environ.items():
            if key.startswith(prefix):
                kid = key[len(prefix) :]
                token_private_keys[kid] = value
        return KeyStore(token_private_keys)

    @staticmethod
    def _current_time() -> datetime:
        return datetime.now(timezone.utc)

    def generate_token(
        self,
        subject: str,
        extra_claims: dict[str, Any] | None = None,
        not_before: timedelta | None = None,
    ) -> str:
        now = self._current_time()
        expires_at = now + self.settings.expiry_duration
        not_before_time = now + (not_before or timedelta(seconds=0))
        token_id = secrets.token_urlsafe(24)

        claims: dict[str, Any] = {
            "iss": self.settings.issuer,
            "aud": self.settings.audience,
            "pur": self.settings.purpose,
            "sub": subject,
            "jti": token_id,
            "iat": int(now.timestamp()),
            "nbf": int(not_before_time.timestamp()),
            "exp": int(expires_at.timestamp()),
            "ext": {},
        }

        if extra_claims:
            # Avoid collisions with registered claims
            reserved = {"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "pur"}
            if reserved.intersection(extra_claims.keys()):
                raise ValueError("extra_claims collides with registered claims")
            claims["ext"] = extra_claims

        token = self.key_store.sign_token(claims=claims)
        return token

    def validate_token(
        self,
        token: str,
        allow_reuse: bool = False,
    ) -> ClaimDict:
        """
        Validate signature, lifetime, audience, issuer, purpose; enforce replay protection by default.
        Returns decoded claims if valid; raises InvalidTokenError on failure.
        """

        # Peek header for key_id
        try:
            unverified_header = get_unverified_header(token)
            key_id = unverified_header.get("kid")
            if not key_id:
                raise InvalidTokenError("Missing 'kid'")
        except InvalidTokenError as error:
            raise InvalidTokenError(f"Invalid header: {error}") from error

        # Fetch public key
        public_key_pem = self.key_store.get_public_key(key_id=key_id)

        # Decode & validate time-based claims + audience/issuer
        try:
            claims: ClaimDict = decode(
                token,
                key=public_key_pem,
                algorithms=["EdDSA"],
                audience=self.settings.audience,
                issuer=self.settings.issuer,
                leeway=self.settings.clock_skew_leeway,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "pur",
                        "sub",
                        "jti",
                        "iat",
                        "nbf",
                        "exp",
                    ],
                },
            )
        except InvalidTokenError:
            raise

        # Purpose scoping
        if claims.get("pur") != self.settings.purpose:
            raise InvalidTokenError("Token purpose mismatch")

        # Replay prevention
        token_id = claims["jti"]
        ttl_seconds = max(1, int(claims["exp"] - time.time()))
        if self.settings.prevent_replay:
            if self.replay_cache.is_used(token_id):
                if not allow_reuse:
                    raise InvalidTokenError("Token has already been used/revoked")
            else:
                # Mark token as used for remaining TTL
                self.replay_cache.mark_as_used(token_id, ttl_seconds)

        return claims

    def revoke_token(self, token: str) -> None:
        """Explicitly revoke a token (e.g., on user action)."""
        try:
            unverified_claims = decode(token, options={"verify_signature": False})
            token_id = unverified_claims.get("jti")
            expires_at = int(unverified_claims.get("exp", 0))
        except Exception:
            # If we can't parse safely, do nothing (or log).
            return
        ttl_seconds = max(1, expires_at - int(time.time()))
        self.replay_cache.revoke_token(token_id, ttl_seconds)
