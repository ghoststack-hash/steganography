"""Authenticated encryption for message payloads.

Design decisions
----------------
* **Cipher:** AES-256-GCM (authenticated encryption).  The GCM tag makes
  any modification of the ciphertext — or use of the wrong passphrase —
  detectable at extraction time.
* **Key derivation:** PBKDF2-HMAC-SHA256 with a 16-byte random salt and
  600,000 iterations (the OWASP 2023 recommendation for this primitive).
* **Storage layout:** ``salt || nonce || ciphertext+tag``.  The salt and
  the nonce are *not* secret; only the derived key matters, so nothing
  about the passphrase itself is ever written into the image.

Only the well-audited ``cryptography`` package is used; no primitive is
implemented by hand.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import PassphraseError

__all__ = [
    "ENCRYPTED_OVERHEAD",
    "KEY_SIZE",
    "NONCE_SIZE",
    "PBKDF2_ITERATIONS",
    "SALT_SIZE",
    "TAG_SIZE",
    "decrypt_bytes",
    "derive_key",
    "encrypt_bytes",
]

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000

#: Extra bytes an encrypted payload needs compared to the plaintext:
#: salt (16) + nonce (12) + GCM authentication tag (16).
ENCRYPTED_OVERHEAD = SALT_SIZE + NONCE_SIZE + TAG_SIZE


def _check_password(password: str) -> None:
    if not isinstance(password, str):
        raise TypeError(f"password must be a str, got {type(password).__name__}")
    if not password:
        raise ValueError("password must be a non-empty string (use None to store unencrypted)")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from *password* and *salt* (PBKDF2-HMAC-SHA256)."""
    _check_password(password)
    if len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be exactly {SALT_SIZE} bytes, got {len(salt)}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM and return ``salt || nonce || ciphertext``."""
    _check_password(password)
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError(f"plaintext must be bytes, got {type(plaintext).__name__}")
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), associated_data=None)
    return salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Reverse :func:`encrypt_bytes`.

    Raises :class:`PassphraseError` when the passphrase is wrong or the
    blob has been modified (GCM authentication failure).
    """
    _check_password(password)
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError(f"blob must be bytes, got {type(blob).__name__}")
    blob = bytes(blob)
    if len(blob) < ENCRYPTED_OVERHEAD:
        raise ValueError(
            f"ciphertext too short: {len(blob)} bytes, expected at least {ENCRYPTED_OVERHEAD}"
        )
    salt, nonce, ciphertext = blob[:SALT_SIZE], blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE], blob[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise PassphraseError(
            "decryption failed: the passphrase is wrong or the payload was modified"
        ) from exc
