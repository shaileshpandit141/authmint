from __future__ import annotations
import redis
from os import environ


class JtiStore:
    """
    Stores used or revoked JTIs in Redis with an expiry matching token TTL.
    Use a dedicated Redis DB or prefix.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        prefix: str = "token:jti:",
    ) -> None:
        self._redis = redis.from_url(  # type: ignore
            redis_url or environ.get("REDIS_URL", "redis://localhost:6379/0")
        )
        self._prefix = prefix
        
    def _key(self, jti: str) -> str:
        return f"{self._prefix}{jti}"
    
    def mark(self, jti: str, ttl_seconds: int) -> None:
        # Set NX to avoid extending a previously set revocation (conservative).
        self._redis.set(self._key(jti), 1, ex=ttl_seconds, nx=True)

    def exists(self, jti: str) -> bool:
        return bool(self._redis.exists(self._key(jti)))

    def revoke(self, jti: str, ttl_seconds: int) -> None:
        # Force set with expiry (overwrites if present).
        self._redis.set(self._key(jti), 1, ex=ttl_seconds)
