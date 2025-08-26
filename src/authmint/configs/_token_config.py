from __future__ import annotations
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class TokenConfig:
    """
    Configuration for token generation and validation.

    Attributes:
        issuer (str): The entity that issues the token.
        audience (str): The intended recipient(s) of the token.
        purpose (str): The purpose or use-case for the token.
        timeout (timedelta): The duration for which the token is valid.
        leeway_seconds (int): Allowed clock skew in seconds (default: 10).
        replay_prevent (bool): Whether to prevent token replay attacks (default: True).

    Example:
    ```
        config = TokenConfig(
            issuer="my-app",
            audience="my-service",
            purpose="access",
            timeout=timedelta(minutes=15)
        )
    ```
    """

    issuer: str
    audience: str
    purpose: str
    timeout: timedelta
    leeway_seconds: int = 10
    replay_prevent: bool = True
