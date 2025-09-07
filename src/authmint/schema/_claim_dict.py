from typing import Any, TypedDict


class ClaimDict(TypedDict):
    iss: str
    aud: str
    sub: str
    jti: str
    pur: str
    iat: int
    nbf: int
    exp: int
    ext: dict[str, Any]
