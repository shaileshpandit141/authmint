from typing import Any
from authmint.configs import TokenConfig
from authmint.managers import KeyManager
from authmint.stores import JtiStore
from datetime import datetime, timedelta, timezone
import secrets
import jwt
from jwt import InvalidTokenError
import time


class TokenService:
    """
    High-level API to issue and verify limited-time tokens with strict scoping.
    """

    def __init__(
        self,
        key_manager: KeyManager,
        jti_store: JtiStore | None = None,
    ) -> None:
        self.key_manager = key_manager
        self.jti_store = jti_store or JtiStore()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    def issue(
        self,
        sub: str,
        config: TokenConfig,
        extra_claims: dict[str, Any] | None = None,
        not_before: timedelta | None = None,
    ) -> str:
        now = self._now()
        exp = now + config.timeout
        nbf = now + (not_before or timedelta(seconds=0))
        jti = secrets.token_urlsafe(24)

        claims: dict[str, Any] = {
            "iss": config.issuer,
            "aud": config.audience,
            "sub": sub,
            "iat": int(now.timestamp()),
            "nbf": int(nbf.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": jti,
            "purpose": config.purpose,
        }

        if extra_claims:
            # Avoid collisions with registered claims
            restricted = {"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "purpose"}
            if restricted.intersection(extra_claims.keys()):
                raise ValueError("extra_claims collides with registered claims")
            claims.update(extra_claims)

        token = self.key_manager.sign(
            payload=claims,
        )

        return token

    def verify(
        self,
        token: str,
        expected: TokenConfig,
        accept_reuse: bool = False,
    ) -> dict[str, Any]:
        """
        Verify signature, lifetime, audience, issuer, purpose; enforce replay protection by default.
        Returns decoded claims if valid; raises InvalidTokenError on failure.
        """

        # Peek header for kid
        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            if not kid:
                raise InvalidTokenError("Missing 'kid'")
        except jwt.InvalidTokenError as error:
            raise InvalidTokenError(f"Invalid header: {error}") from error

        # Fetch public key
        pub_pem = self.key_manager.get_public_key(kid=kid)

        # Decode & validate time-based claims + audience/issuer
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=pub_pem,
                algorithms=["EdDSA"],
                audience=expected.audience,
                issuer=expected.issuer,
                leeway=expected.leeway_seconds,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "iat",
                        "nbf",
                        "exp",
                        "jti",
                        "purpose",
                    ],
                },
            )
        except InvalidTokenError:
            raise

        # Purpose scoping
        if claims.get("purpose") != expected.purpose:
            raise InvalidTokenError("Token purpose mismatch")

        # Replay prevention
        jti = claims["jti"]
        ttl_seconds = max(1, int(claims["exp"] - time.time()))
        if expected.replay_prevent:
            if self.jti_store.exists(jti):
                if not accept_reuse:
                    raise InvalidTokenError("Token has already been used/revoked")
            else:
                # mark JTI as used for remaining TTL
                self.jti_store.mark(jti, ttl_seconds)

        return claims

    def revoke(self, token: str) -> None:
        """Explicitly revoke a token (e.g., on user action)."""
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            jti = unverified.get("jti")
            exp = int(unverified.get("exp", 0))
        except Exception:
            # If we can't parse safely, do nothing (or log).
            return
        ttl_seconds = max(1, exp - int(time.time()))
        self.jti_store.revoke(jti, ttl_seconds)
