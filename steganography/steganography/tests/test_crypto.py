import pytest

from steganography import crypto
from steganography.exceptions import PassphraseError


def test_round_trip():
    blob = crypto.encrypt_bytes(b"attack at dawn", "correct horse")
    assert crypto.decrypt_bytes(blob, "correct horse") == b"attack at dawn"


def test_round_trip_empty_plaintext():
    blob = crypto.encrypt_bytes(b"", "pw")
    assert crypto.decrypt_bytes(blob, "pw") == b""


def test_wrong_password_raises():
    blob = crypto.encrypt_bytes(b"secret", "right")
    with pytest.raises(PassphraseError):
        crypto.decrypt_bytes(blob, "wrong")


def test_tampered_ciphertext_raises(rng):
    blob = bytearray(crypto.encrypt_bytes(b"secret", "pw"))
    blob[-1] ^= 0x01  # flip a bit inside the GCM tag
    with pytest.raises(PassphraseError):
        crypto.decrypt_bytes(bytes(blob), "pw")


def test_ciphertext_is_randomised():
    a = crypto.encrypt_bytes(b"same", "pw")
    b = crypto.encrypt_bytes(b"same", "pw")
    assert a != b  # fresh salt and nonce every time
    assert crypto.decrypt_bytes(a, "pw") == b"same"
    assert crypto.decrypt_bytes(b, "pw") == b"same"


def test_blob_layout():
    blob = crypto.encrypt_bytes(b"x", "pw")
    assert len(blob) == crypto.ENCRYPTED_OVERHEAD + 1


def test_derive_key_is_deterministic():
    salt = bytes(range(16))
    k1 = crypto.derive_key("pw", salt)
    k2 = crypto.derive_key("pw", salt)
    assert k1 == k2 and len(k1) == crypto.KEY_SIZE


def test_derive_key_salt_changes_key():
    k1 = crypto.derive_key("pw", bytes(16))
    k2 = crypto.derive_key("pw", b"\x01" * 16)
    assert k1 != k2


def test_input_validation():
    with pytest.raises(ValueError):
        crypto.derive_key("", bytes(16))
    with pytest.raises(ValueError):
        crypto.encrypt_bytes(b"x", "")
    with pytest.raises(TypeError):
        crypto.encrypt_bytes(b"x", None)
    with pytest.raises(ValueError):
        crypto.derive_key("pw", b"short")


def test_real_pbkdf2_cost(monkeypatch):
    """Sanity check with the production iteration count (~0.3 s)."""
    monkeypatch.setattr(crypto, "PBKDF2_ITERATIONS", 600_000)
    assert crypto.PBKDF2_ITERATIONS >= 100_000
    blob = crypto.encrypt_bytes(b"slow but strong", "pw")
    assert crypto.decrypt_bytes(blob, "pw") == b"slow but strong"
