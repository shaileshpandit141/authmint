from __future__ import annotations
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class TokenSettings:
    """
    Settings for token generation and validation.

    Attributes:
        token_issuer (str): The entity that issues the token.
        token_audience (str): The intended recipient(s) of the token.
        token_purpose (str): The purpose or use-case for the token.
        expiry_duration (timedelta): The duration for which the token is valid.
        clock_skew_leeway (int): Allowed clock skew in seconds (default: 10).
        prevent_replay (bool): Whether to prevent token replay attacks (default: True).

    Example:
    ```
        settings = TokenSettings(
            token_issuer="my-app",
            token_audience="my-service",
            token_purpose="access",
            expiry_duration=timedelta(minutes=15)
        )
    ```
    """

    token_issuer: str
    token_audience: str
    token_purpose: str
    expiry_duration: timedelta
    clock_skew_leeway: int = 10
    prevent_replay: bool = True
