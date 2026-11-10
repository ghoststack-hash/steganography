"""Least-significant-bit steganography engine.

This module implements the container format and the embed/extract
primitives.  One payload bit is stored in the least significant bit of
every colour-channel value, scanned in row-major order over an
``(H, W, 3)`` uint8 array.  Each touched channel value changes by at
most 1, which is imperceptible — unlike naive "replace the whole byte"
schemes that visibly repaint pixels.

Container format (version 2)::

    Offset  Size  Field
    0       2     Magic bytes b"ST"
    2       1     Format version (2)
    3       1     Flags — bit 0: payload encrypted, bits 1-7 reserved
    4       4     Payload length in bytes (uint32, big-endian)
    8       4     CRC-32 of bytes 0-7 (uint32, big-endian)
    12      N     Payload: ciphertext, or raw UTF-8 message bytes

Bits within a byte are written most-significant first.  The CRC-32 lets
extraction tell "this is not a stego image" and "this image is
corrupted" apart from "wrong passphrase" (which surfaces as a GCM
authentication failure instead).

File helpers (:func:`embed_file`, :func:`extract_file`) normalise every
input to an RGB channel order before embedding, so stego images stay
readable with any library that preserves exact pixel values (PIL,
imageio, ...), not only OpenCV.  Only lossless containers (PNG, BMP,
TIFF) are accepted as output; a JPEG would destroy the hidden bits.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import cv2
import numpy as np

from . import crypto
from .exceptions import (
    CapacityError,
    FormatError,
    ImageError,
    PassphraseError,
    UnsupportedFormatError,
    UnsupportedVersionError,
)

__all__ = [
    "ENCRYPTED_OVERHEAD",
    "FLAG_ENCRYPTED",
    "HEADER_SIZE",
    "LOSSLESS_SUFFIXES",
    "MAGIC",
    "VERSION",
    "capacity_bytes",
    "embed",
    "embed_file",
    "extract",
    "extract_file",
    "load_image",
    "message_capacity",
]

MAGIC = b"ST"
VERSION = 2
FLAG_ENCRYPTED = 0x01
HEADER_SIZE = 12
ENCRYPTED_OVERHEAD = crypto.ENCRYPTED_OVERHEAD

#: Output containers that preserve every pixel value exactly.
LOSSLESS_SUFFIXES = {".png", ".bmp", ".tif", ".tiff"}

_HEADER_STRUCT = struct.Struct(">2sBBII")  # magic, version, flags, length, crc32


# ---------------------------------------------------------------------------
# Array-level primitives
# ---------------------------------------------------------------------------

def _validate_color_image(image: np.ndarray) -> np.ndarray:
    arr = np.asarray(image)
    if arr.dtype != np.uint8:
        raise ImageError(f"expected a uint8 image array, got {arr.dtype}")
    if arr.ndim != 3 or arr.shape[2] != 3:
        raise ImageError(f"expected an (H, W, 3) colour image array, got shape {arr.shape}")
    return arr


def embed(image: np.ndarray, message: str, *, password: str | None = None) -> np.ndarray:
    """Embed *message* into *image* (an ``(H, W, 3)`` uint8 array) and return a copy.

    Args:
        image: Cover image.  The input array is never modified.
        message: Text to hide (stored as UTF-8).
        password: Non-empty passphrase to encrypt the payload with
            AES-256-GCM, or ``None`` to store the message unencrypted.

    Returns:
        A new array with the message hidden in the least significant
        bits.  Channel values change by at most 1.

    Raises:
        ValueError: If *password* is an empty string.
        CapacityError: If the image cannot hold the payload.
        ImageError: If *image* is not a uint8 ``(H, W, 3)`` array.
    """
    arr = _validate_color_image(image)
    if not isinstance(message, str):
        raise TypeError(f"message must be a str, got {type(message).__name__}")
    if password is not None:
        crypto._check_password(password)  # reject empty passphrases early

    plaintext = message.encode("utf-8")
    payload = crypto.encrypt_bytes(plaintext, password) if password else plaintext
    if len(payload) > 0xFFFF_FFFF:
        raise CapacityError("payload exceeds the 4 GiB header limit")

    flags = FLAG_ENCRYPTED if password else 0
    header8 = _HEADER_STRUCT.pack(MAGIC, VERSION, flags, len(payload), 0)[:8]
    header = header8 + struct.pack(">I", zlib.crc32(header8) & 0xFFFF_FFFF)

    bits = np.unpackbits(np.frombuffer(header + payload, dtype=np.uint8))
    flat = np.array(arr, copy=True, order="C").reshape(-1)
    if bits.size > flat.size:
        raise CapacityError(
            f"image can hold {flat.size // 8} bytes but this message needs "
            f"{(bits.size + 7) // 8} bytes (including the {HEADER_SIZE}-byte header"
            f"{' and ' + str(ENCRYPTED_OVERHEAD) + ' bytes of encryption overhead' if password else ''}); "
            "use a larger image or a shorter message"
        )
    idx = np.arange(bits.size)
    flat[idx] = (flat[idx] & 0xFE) | bits
    return flat.reshape(arr.shape)


def extract(image: np.ndarray, *, password: str | None = None) -> str:
    """Extract the hidden message from an ``(H, W, 3)`` uint8 array.

    Raises:
        FormatError: If the image holds no intact message (bad magic,
            CRC mismatch, truncated payload, or non-UTF-8 plaintext).
        UnsupportedVersionError: If the format version differs.
        PassphraseError: If the payload is encrypted but no password was
            given, the password is wrong, or the ciphertext was modified.
        ImageError: If *image* is not a uint8 ``(H, W, 3)`` array.
    """
    arr = _validate_color_image(image)
    flat = arr.reshape(-1)
    if flat.size < HEADER_SIZE * 8:
        raise FormatError(f"image is too small to contain a message ({flat.size // 8} bytes capacity)")

    def _read(offset_bytes: int, count: int) -> bytes:
        start = offset_bytes * 8
        return np.packbits(flat[start:start + count * 8] & 1).tobytes()

    header = _read(0, HEADER_SIZE)
    magic, version, flags, length, crc = _HEADER_STRUCT.unpack(header)
    if magic != MAGIC:
        raise FormatError("no hidden message found (magic bytes mismatch)")
    if version != VERSION:
        raise UnsupportedVersionError(
            f"format version {version} is not supported (expected {VERSION})"
        )
    if zlib.crc32(header[:8]) & 0xFFFF_FFFF != crc:
        raise FormatError("header CRC mismatch: the image was corrupted or modified")
    if HEADER_SIZE + length > flat.size // 8:
        raise FormatError(
            f"payload truncated: header claims {length} bytes but only "
            f"{flat.size // 8 - HEADER_SIZE} are available"
        )

    payload = _read(HEADER_SIZE, length)
    if flags & FLAG_ENCRYPTED:
        if not password:
            raise PassphraseError("this image holds an encrypted message; a passphrase is required")
        if len(payload) < ENCRYPTED_OVERHEAD:
            raise FormatError(
                f"encrypted payload is too short ({length} bytes); the image is corrupted"
            )
        payload = crypto.decrypt_bytes(payload, password)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FormatError("payload is not valid UTF-8; the image is corrupted") from exc


# ---------------------------------------------------------------------------
# Capacity helpers
# ---------------------------------------------------------------------------

def capacity_bytes(shape: tuple[int, ...]) -> int:
    """Total number of payload bytes an ``(H, W[, 3])`` image can hold, header included."""
    if len(shape) < 2:
        raise ValueError(f"shape must have at least two dimensions, got {shape}")
    return (shape[0] * shape[1] * 3) // 8 - HEADER_SIZE


def message_capacity(shape: tuple[int, ...], *, encrypted: bool = False) -> int:
    """Largest message (UTF-8 encoded) that fits, accounting for header/encryption overhead."""
    cap = capacity_bytes(shape)
    return max(0, cap - (ENCRYPTED_OVERHEAD if encrypted else 0))


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def _load_color(path: str | Path) -> tuple[np.ndarray, np.ndarray | None]:
    """Load *path* as a canonical RGB ``(H, W, 3)`` uint8 array plus its alpha channel."""
    path = Path(path)
    img = cv2.imread(str(path), cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ImageError(f"could not read image: {path}")
    img = np.asarray(img)
    if img.dtype != np.uint8:
        raise ImageError(
            f"{path.name} has pixel depth {img.dtype}; only 8-bit images are supported"
        )

    alpha: np.ndarray | None = None
    if img.ndim == 2:
        img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
    elif img.ndim == 3 and img.shape[2] == 2:  # grayscale + alpha
        gray, alpha = cv2.split(img)
        img = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
    elif img.ndim == 3 and img.shape[2] == 3:
        pass
    elif img.ndim == 3 and img.shape[2] == 4:
        b, g, r, alpha = cv2.split(img)
        img = cv2.merge((b, g, r))
    else:
        raise ImageError(f"{path.name} has an unsupported channel layout: shape {img.shape}")

    rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    return np.ascontiguousarray(rgb), alpha


def load_image(path: str | Path) -> np.ndarray:
    """Load *path* as a canonical RGB ``(H, W, 3)`` uint8 array."""
    rgb, _ = _load_color(path)
    return rgb


def _save_color(path: str | Path, rgb: np.ndarray, alpha: np.ndarray | None) -> None:
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in LOSSLESS_SUFFIXES:
        raise UnsupportedFormatError(
            f"{suffix!r} would re-encode pixels and destroy the hidden bits; "
            f"save as one of: {', '.join(sorted(LOSSLESS_SUFFIXES))}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    if alpha is not None:
        bgr = cv2.merge((*cv2.split(bgr), alpha))
    ok, buf = cv2.imencode(suffix, bgr)
    if not ok:
        raise ImageError(f"could not encode image as {path}")
    path.write_bytes(buf.tobytes())


def embed_file(
    input_path: str | Path,
    output_path: str | Path,
    message: str,
    *,
    password: str | None = None,
) -> None:
    """Hide *message* in the image at *input_path* and write the result to *output_path*.

    The output container must be lossless (PNG, BMP, TIFF).  Grayscale
    inputs are stored as visually identical 3-channel images; alpha
    channels are carried over untouched.
    """
    rgb, alpha = _load_color(input_path)
    stego = embed(rgb, message, password=password)
    _save_color(output_path, stego, alpha)


def extract_file(path: str | Path, *, password: str | None = None) -> str:
    """Extract the hidden message from the stego image at *path*."""
    rgb, _ = _load_color(path)
    return extract(rgb, password=password)
