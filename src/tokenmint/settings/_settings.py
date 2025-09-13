from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class Settings:
    """
    Settings for token generation and validation.

    Attributes:
        issuer (str): The entity that issues the token.
        audience (str): The intended recipient(s) of the token.
        purpose (str): The purpose or use-case for the token.
        expiry_duration (timedelta): The duration for which the token is valid.
        clock_skew_leeway (int): Allowed clock skew in seconds (default: 10).
        prevent_replay (bool): Whether to prevent token replay attacks (default: True).

    Example:
    ```
        settings = Settings(
            issuer="my-app",
            audience="my-service",
            purpose="access",
            expiry_duration=timedelta(minutes=15)
        )
    ```
    """

    issuer: str
    audience: str
    purpose: str
    expiry_duration: timedelta
    clock_skew_leeway: int = 10
    prevent_replay: bool = True
