from __future__ import annotations
import redis


class ReplayCache:
    """
    Stores used or revoked token IDs (JTIs) in Redis with an expiry matching token lifetime.
    Use a dedicated Redis DB or key prefix.
    """

    def __init__(
        self,
        redis_url: str,
        key_prefix: str = "token:jti:",
    ) -> None:
        self._redis_client = redis.from_url(redis_url)  # type: ignore
        self._key_prefix = key_prefix

    def _build_key(self, token_id: str) -> str:
        return f"{self._key_prefix}{token_id}"

    def mark_as_used(self, token_id: str, ttl_seconds: int) -> None:
        """Mark a token as used (cannot be reused)."""
        self._redis_client.set(self._build_key(token_id), 1, ex=ttl_seconds, nx=True)

    def is_used(self, token_id: str) -> bool:
        """Check if a token ID has already been used/revoked."""
        return bool(self._redis_client.exists(self._build_key(token_id)))

    def revoke_token(self, token_id: str, ttl_seconds: int) -> None:
        """Revoke a token explicitly, forcing Redis to track it until expiry."""
        self._redis_client.set(self._build_key(token_id), 1, ex=ttl_seconds)
