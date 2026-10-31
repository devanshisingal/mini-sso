"""
Tests for Argon2id password hashing and secret cipher encryption.
"""

from app.core.security import (
    SecretCipher,
    generate_secure_token,
    hash_password,
    verify_password,
)


def test_argon2id_hashing_and_verification():
    password = "SuperSecretPassword123!"
    hashed = hash_password(password)

    # Argon2id produces string starting with $argon2id$
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


def test_argon2id_generates_unique_salts():
    password = "SamePasswordEveryTime"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Two hashes of identical password must differ due to unique salts
    assert hash1 != hash2
    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True


def test_secret_cipher_roundtrip():
    cipher = SecretCipher(key="my-custom-encryption-key-for-test")
    raw_secret = "JBSWY3DPEHPK3PXP"

    ciphertext = cipher.encrypt(raw_secret)
    assert ciphertext != raw_secret
    assert cipher.decrypt(ciphertext) == raw_secret


def test_generate_secure_token():
    t1 = generate_secure_token(32)
    t2 = generate_secure_token(32)
    assert len(t1) > 32
    assert t1 != t2
