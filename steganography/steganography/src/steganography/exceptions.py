"""Exception hierarchy for the steganography package.

Every error raised intentionally by this library derives from
:class:`SteganographyError`, so callers can catch a single base class.
"""

from __future__ import annotations

__all__ = [
    "CapacityError",
    "FormatError",
    "ImageError",
    "PassphraseError",
    "SteganographyError",
    "UnsupportedFormatError",
    "UnsupportedVersionError",
]


class SteganographyError(Exception):
    """Base class for all errors raised by this package."""


class ImageError(SteganographyError):
    """The image could not be read, written, or has an unsupported layout."""


class UnsupportedFormatError(ImageError):
    """The requested operation is impossible for this file format.

    Raised, for example, when the output path uses a lossy container
    (JPEG/WebP) that would destroy the hidden bits.
    """


class CapacityError(SteganographyError):
    """The image is too small to hold the message."""


class FormatError(SteganographyError):
    """The image does not contain a valid, intact hidden message.

    Raised when the magic bytes, CRC-32 or payload structure do not
    match the container format.
    """


class UnsupportedVersionError(FormatError):
    """The stego image was written by an incompatible format version."""


class PassphraseError(SteganographyError):
    """Decryption failed: the passphrase is wrong or the payload was modified."""
