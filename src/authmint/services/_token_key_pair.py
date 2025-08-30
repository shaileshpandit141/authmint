from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class TokenKeyPair:
    """Handles generation of Ed25519 key pairs for tokens."""

    def __init__(self) -> None:
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    def private_key(self) -> str:
        """Return PEM-encoded private key."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def public_key(self) -> str:
        """Return PEM-encoded public key."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
