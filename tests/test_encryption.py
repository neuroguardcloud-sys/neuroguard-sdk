"""Unit tests for the encryption module."""

import pytest

from neuroguard.encryption import NeuralDataCipher


def test_encrypt_decrypt_roundtrip_with_key() -> None:
    """Encrypting and decrypting with a generated key returns original data."""
    cipher = NeuralDataCipher()
    data = b"neural signal data"
    encrypted = cipher.encrypt(data)
    assert encrypted != data
    assert cipher.decrypt(encrypted) == data


def test_encrypt_decrypt_roundtrip_with_secret() -> None:
    """Encrypting with a secret (passphrase) produces salt+token; decrypt restores data."""
    cipher = NeuralDataCipher(secret="user-secret")
    data = b"biometric payload"
    encrypted = cipher.encrypt(data)
    assert len(encrypted) > len(data)
    assert cipher.decrypt(encrypted) == data


def test_from_secret_restores_decryption() -> None:
    """After persisting salt, from_secret(secret, salt) can decrypt payloads."""
    secret = "passphrase"
    cipher1 = NeuralDataCipher(secret=secret)
    salt = cipher1.get_salt()
    assert salt is not None
    encrypted = cipher1.encrypt(b"sensitive")
    cipher2 = NeuralDataCipher.from_secret(secret, salt)
    assert cipher2.decrypt(encrypted) == b"sensitive"


def test_different_secrets_produce_different_ciphertext() -> None:
    """Same plaintext with different secrets must not match."""
    c1 = NeuralDataCipher(secret="secret1")
    c2 = NeuralDataCipher(secret="secret2")
    data = b"same data"
    assert c1.encrypt(data) != c2.encrypt(data)


def test_generate_key_returns_valid_key() -> None:
    """Generated key can be used to construct a cipher."""
    key = NeuralDataCipher.generate_key()
    cipher = NeuralDataCipher(key=key)
    assert cipher.decrypt(cipher.encrypt(b"x")) == b"x"
