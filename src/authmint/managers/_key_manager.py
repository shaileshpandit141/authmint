from __future__ import annotations
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from os import environ
from jwt import encode, InvalidTokenError


class KeyManager:
    """
    Holds Ed25519 private keys, exposes public JWKs for verification, supports rotation via `kid`.
    In production, load from a KMS/HSM or sealed config; never hard-code keys.
    """

    def __init__(self, jwk_set: dict[str, str]) -> None:
        """
        jwk_set: { kid: PEM-encoded Ed25519 private key (PKCS8) }
        Keep exactly one 'current' KID in env: TOKEN_CURRENT_KID
        """
        self._priv_keys: dict[str, ed25519.Ed25519PrivateKey] = {}
        self._pub_keys_pem: dict[str, bytes] = {}

        for kid, pem in jwk_set.items():
            priv = serialization.load_pem_private_key(pem.encode(), password=None)
            if not isinstance(priv, ed25519.Ed25519PrivateKey):
                raise ValueError(f"KID {kid} is not an Ed25519 private key")
            self._priv_keys[kid] = priv
            self._pub_keys_pem[kid] = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        current = environ.get("TOKEN_CURRENT_KID")
        if not current or current not in self._priv_keys:
            raise RuntimeError("TOKEN_CURRENT_KID must reference a key in jwk_set")
        self._current_kid = current

    @property
    def current_kid(self) -> str:
        return self._current_kid

    def sign(self, payload: dict[str, Any]) -> str:
        kid = self._current_kid
        priv = self._priv_keys[kid]
        headers = {"kid": kid, "typ": "JWT", "alg": "EdDSA"}
        return encode(payload, priv, algorithm="EdDSA", headers=headers)

    def get_public_key(self, kid: str) -> bytes:
        try:
            return self._pub_keys_pem[kid]
        except KeyError:
            raise InvalidTokenError("Unknown key id")

    def public_jwks(self) -> dict[str, str]:
        """Expose for JWKS endpoint if you have third-party verifiers."""
        out: dict[str, str] = {}
        for kid, pem in self._pub_keys_pem.items():
            out[kid] = pem.decode()
        return out
