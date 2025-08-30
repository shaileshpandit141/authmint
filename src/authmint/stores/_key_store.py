from __future__ import annotations

from os import environ
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from jwt import InvalidTokenError, encode
from authmint.exceptions import TokenConfigurationError


class KeyStore:
    """
    Manages Ed25519 private keys, exposes public JWKs for verification,
    and supports key rotation via `key_id`.

    In production, keys should be loaded from a secure source
    (e.g., KMS/HSM or sealed config), never hard-coded.
    """

    def __init__(self, private_key_map: dict[str, str]) -> None:
        """
        private_key_map: { key_id: PEM-encoded Ed25519 private key (PKCS8) }
        Environment must contain TOKEN_ACTIVE_KEY_ID pointing to the active key.
        """
        self._private_keys: dict[str, ed25519.Ed25519PrivateKey] = {}
        self._public_keys_pem: dict[str, bytes] = {}

        for key_id, pem in private_key_map.items():
            private_key = serialization.load_pem_private_key(
                pem.encode(),
                password=None,
            )
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError(f"Key ID {key_id} is not an Ed25519 private key")
            self._private_keys[key_id] = private_key
            self._public_keys_pem[key_id] = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        active = environ.get("TOKEN_ACTIVE_KEY_ID")
        if not active:
            raise TokenConfigurationError(
                "The TOKEN_ACTIVE_KEY_ID environment variable is missing. "
                "You must set it to the identifier of your active private key, for example:\n\n"
                "    TOKEN_ACTIVE_KEY_ID = '2025-08-rot-1'"
            )

        if active not in self._private_keys:
            raise TokenConfigurationError(
                f"TOKEN_ACTIVE_KEY_ID is set to '{active}', but no matching "
                f"TOKEN_PRIVATE_KEY_{active} environment variable was found. "
                "Make sure both variables are defined, for example:\n\n"
                "    TOKEN_ACTIVE_KEY_ID = '2025-08-rot-1'\n"
                "    TOKEN_PRIVATE_KEY_2025-08-rot-1 = '<your-private-key>'"
            )
        self._active_key_id = active

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    def sign_token(self, claims: dict[str, Any]) -> str:
        """Sign JWT claims with the active private key."""
        key_id = self._active_key_id
        private_key = self._private_keys[key_id]
        headers = {"kid": key_id, "typ": "JWT", "alg": "EdDSA"}
        return encode(claims, private_key, algorithm="EdDSA", headers=headers)

    def get_public_key(self, key_id: str) -> bytes:
        """Retrieve the PEM-encoded public key for a given key ID."""
        try:
            return self._public_keys_pem[key_id]
        except KeyError:
            raise InvalidTokenError("Unknown key id")

    def export_public_jwks(self) -> dict[str, str]:
        """Expose public JWKs for verification by third-party services."""
        return {key_id: pem.decode() for key_id, pem in self._public_keys_pem.items()}
