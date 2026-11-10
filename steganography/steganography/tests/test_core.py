import numpy as np
import pytest

from steganography import (
    ENCRYPTED_OVERHEAD,
    HEADER_SIZE,
    CapacityError,
    FormatError,
    ImageError,
    PassphraseError,
    UnsupportedVersionError,
    embed,
    extract,
    message_capacity,
)

LONG_UNICODE_MESSAGE = (
    "The quick brown fox jumps over the lazy dog. "
    "包装机密数据 — 数据隐藏测试。 "
    "Ελληνικά, Россия, العربية … "
    "Emoji work too: 🚀🔒🌊 "
) + ("A" * 400)


def write_raw_bits(image: np.ndarray, data: bytes) -> np.ndarray:
    """Low-level helper that writes *data* into the LSBs in container bit order."""
    flat = image.reshape(-1).copy()
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits
    return flat.reshape(image.shape)


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("password", [None, "hunter2"])
def test_round_trip(rgb_image, password):
    message = LONG_UNICODE_MESSAGE
    stego = embed(rgb_image, message, password=password)
    assert extract(stego, password=password) == message


def test_round_trip_ascii(rgb_image):
    stego = embed(rgb_image, "meet at noon", password="p@ss")
    assert extract(stego, password="p@ss") == "meet at noon"


@pytest.mark.parametrize("password", [None, "hunter2"])
def test_round_trip_empty_message(rgb_image, password):
    stego = embed(rgb_image, "", password=password)
    assert extract(stego, password=password) == ""


def test_wrong_password_raises(rgb_image):
    stego = embed(rgb_image, "secret", password="right")
    with pytest.raises(PassphraseError):
        extract(stego, password="wrong")


def test_missing_password_on_encrypted_image_raises(rgb_image):
    stego = embed(rgb_image, "secret", password="hunter2")
    with pytest.raises(PassphraseError):
        extract(stego)


def test_tampered_payload_detected_as_wrong_passphrase(rgb_image):
    stego = embed(rgb_image, "secret", password="hunter2")
    flat = stego.reshape(-1)
    flat[HEADER_SIZE * 8 + 8] ^= 1  # flip one ciphertext bit
    with pytest.raises(PassphraseError):
        extract(stego, password="hunter2")


def test_tampered_header_detected_as_corruption(rgb_image):
    stego = embed(rgb_image, "secret", password="hunter2")
    stego.reshape(-1)[40] ^= 1  # bit inside the length field -> CRC must fail
    with pytest.raises(FormatError, match="CRC"):
        extract(stego, password="hunter2")


def test_non_stego_image_raises(rng):
    random_image = rng.integers(0, 256, size=(32, 32, 3), dtype=np.uint8)
    with pytest.raises(FormatError, match="no hidden message"):
        extract(random_image)


def test_unsupported_version_raises(rgb_image):
    import struct
    import zlib

    payload = b"legacy"
    header8 = struct.pack(">2sBBI", b"ST", 1, 0, len(payload))
    blob = header8 + struct.pack(">I", zlib.crc32(header8)) + payload
    crafted = write_raw_bits(rgb_image, blob)
    with pytest.raises(UnsupportedVersionError):
        extract(crafted)


def test_truncated_payload_raises(rgb_image):
    import struct
    import zlib

    header8 = struct.pack(">2sBBI", b"ST", 2, 0, 10**6)
    blob = header8 + struct.pack(">I", zlib.crc32(header8))
    crafted = write_raw_bits(rgb_image, blob)
    with pytest.raises(FormatError, match="truncated"):
        extract(crafted)


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------

def test_capacity_bounds(rgb_image):
    message = "a" * 2000
    with pytest.raises(CapacityError):
        embed(rgb_image, message)


def test_exact_fit_unencrypted():
    # 12x4x3 = 144 bits = 18 bytes = 12 header + 6 message bytes.
    image = np.arange(12 * 4 * 3, dtype=np.uint8).reshape(12, 4, 3)
    assert message_capacity(image.shape) == 6
    stego = embed(image, "abcdef")
    assert extract(stego) == "abcdef"


def test_exact_fit_encrypted():
    # (12 + 44 + 1) bytes = 456 bits = 19x8x3 channel slots.
    image = np.arange(19 * 8 * 3, dtype=np.uint8).reshape(19, 8, 3)
    assert message_capacity(image.shape, encrypted=True) == 1
    stego = embed(image, "x", password="pw")
    assert extract(stego, password="pw") == "x"


def test_one_byte_over_capacity_fails():
    image = np.arange(12 * 4 * 3, dtype=np.uint8).reshape(12, 4, 3)
    with pytest.raises(CapacityError):
        embed(image, "abcdefg")  # 7 bytes > 6-byte capacity


def test_capacity_error_mentions_numbers(rgb_image):
    with pytest.raises(CapacityError, match="bytes"):
        embed(rgb_image, "z" * 10_000)


def test_message_capacity_accounts_for_encryption(rgb_image):
    plain = message_capacity(rgb_image.shape)
    encrypted = message_capacity(rgb_image.shape, encrypted=True)
    assert encrypted == plain - ENCRYPTED_OVERHEAD


def test_tiny_image_cannot_extract(rng):
    tiny = rng.integers(0, 256, size=(3, 3, 3), dtype=np.uint8)  # 27 bytes < 12-byte header
    with pytest.raises(FormatError, match="too small"):
        extract(tiny)


# ---------------------------------------------------------------------------
# Cover-image fidelity
# ---------------------------------------------------------------------------

def test_embed_only_touches_lsb(rgb_image):
    stego = embed(rgb_image, LONG_UNICODE_MESSAGE, password="pw")
    diff = stego.astype(int) - rgb_image.astype(int)
    assert np.abs(diff).max() <= 1
    assert np.count_nonzero(diff) > 0  # something was actually embedded


def test_embed_does_not_mutate_input(rgb_image):
    snapshot = rgb_image.copy()
    embed(rgb_image, "hello", password="pw")
    np.testing.assert_array_equal(rgb_image, snapshot)


def test_embed_is_deterministic(rgb_image):
    # Unencrypted payloads have no random salt/nonce, so embedding is reproducible.
    a = embed(rgb_image, "hello")
    b = embed(rgb_image, "hello")
    np.testing.assert_array_equal(a, b)


def test_encrypted_embeds_use_fresh_randomness(rgb_image):
    a = embed(rgb_image, "hello", password="pw")
    b = embed(rgb_image, "hello", password="pw")
    assert not np.array_equal(a, b)  # random salt/nonce -> different ciphertext
    assert extract(a, password="pw") == extract(b, password="pw") == "hello"


def test_unused_capacity_left_untouched(rgb_image):
    stego = embed(rgb_image, "tiny")
    # 5-char message uses 96 + 40 bits; everything after stays identical.
    start = (HEADER_SIZE + 5) * 8
    np.testing.assert_array_equal(
        stego.reshape(-1)[start:], rgb_image.reshape(-1)[start:]
    )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def test_embed_rejects_non_string_message(rgb_image):
    with pytest.raises(TypeError):
        embed(rgb_image, b"bytes message")


def test_embed_rejects_empty_password(rgb_image):
    with pytest.raises(ValueError):
        embed(rgb_image, "msg", password="")


def test_extract_rejects_bad_arrays(rng):
    with pytest.raises(ImageError):
        extract(rng.integers(0, 256, size=(8, 8), dtype=np.uint8))
    with pytest.raises(ImageError):
        extract(rng.integers(0, 256, size=(8, 8, 4), dtype=np.uint8))
    with pytest.raises(ImageError):
        extract(rng.integers(0, 65536, size=(8, 8, 3), dtype=np.uint16))
