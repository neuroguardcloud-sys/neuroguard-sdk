"""
Neural data encryption engine.

Uses Fernet (symmetric AES-128-CBC + HMAC) with optional key derivation
from a user secret so keys are not stored in plaintext.
"""

from __future__ import annotations

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class NeuralDataCipher:
    """
    Encrypt/decrypt neural or biometric payloads before they leave the device.

    Keys can be generated internally or derived from a user secret (e.g. passphrase)
    via PBKDF2. Data is encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
    """

    SALT_LENGTH = 16
    KDF_ITERATIONS = 120_000

    def __init__(self, key: Optional[bytes] = None, secret: Optional[str] = None):
        """
        Initialize the cipher.

        Args:
            key: Raw 32-byte Fernet key. If None, a key is derived from `secret`
                 or a new key is generated (use get_key() to persist it).
            secret: User secret (e.g. passphrase) for key derivation. Ignored if `key` is set.
        """
        if key is not None:
            self._key = key
            self._fernet = Fernet(key)
            self._salt = None
        elif secret is not None:
            self._salt = os.urandom(self.SALT_LENGTH)
            self._key = self._derive_key(secret.encode("utf-8"), self._salt)
            self._fernet = Fernet(self._key)
        else:
            self._key = Fernet.generate_key()
            self._fernet = Fernet(self._key)
            self._salt = None

    def _derive_key(self, secret: bytes, salt: bytes) -> bytes:
        """Derive a Fernet key from secret and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KDF_ITERATIONS,
        )
        raw = kdf.derive(secret)
        return base64.urlsafe_b64encode(raw)

    @classmethod
    def from_secret(cls, secret: str, salt: bytes) -> "NeuralDataCipher":
        """Create a cipher from a stored salt and the user secret (e.g. after device restart)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=cls.KDF_ITERATIONS,
        )
        raw = kdf.derive(secret.encode("utf-8"))
        key = base64.urlsafe_b64encode(raw)
        instance = cls(key=key)
        instance._salt = salt
        return instance

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt binary data. Returns ciphertext (optionally prepended with salt if derived)."""
        token = self._fernet.encrypt(data)
        if self._salt is not None:
            return self._salt + token
        return token

    def decrypt(self, payload: bytes) -> bytes:
        """
        Decrypt payload. When the cipher was created with a secret, encrypt() returns
        salt + token; in that case the first SALT_LENGTH bytes are salt and the rest
        is decrypted. When the cipher was created with a key only, the whole payload
        is the Fernet token.
        """
        if self._salt is not None and len(payload) > self.SALT_LENGTH:
            token = payload[self.SALT_LENGTH :]
            return self._fernet.decrypt(token)
        return self._fernet.decrypt(payload)

    def get_key(self) -> bytes:
        """Return the raw Fernet key for persistence (store securely)."""
        return self._key

    def get_salt(self) -> Optional[bytes]:
        """Return the salt used for key derivation, if any."""
        return self._salt

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet key."""
        return Fernet.generate_key()
