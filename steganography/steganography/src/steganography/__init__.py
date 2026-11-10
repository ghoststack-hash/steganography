"""steganography — secure least-significant-bit steganography for images.

Hide text messages inside the least significant bits of an image's
colour channels, optionally encrypted with AES-256-GCM under a
passphrase-derived key.  Works on any lossless container (PNG, BMP,
TIFF); JPEG and other lossy formats are rejected on output because they
destroy hidden bits.

Quick start::

    from steganography import embed_file, extract_file

    embed_file("cover.png", "stego.png", "meet at noon", password="hunter2")
    extract_file("stego.png", password="hunter2")

See ``steganography.core`` for the container format specification.
"""

from .core import (
    ENCRYPTED_OVERHEAD,
    HEADER_SIZE,
    LOSSLESS_SUFFIXES,
    MAGIC,
    VERSION,
    capacity_bytes,
    embed,
    embed_file,
    extract,
    extract_file,
    load_image,
    message_capacity,
)
from .exceptions import (
    CapacityError,
    FormatError,
    ImageError,
    PassphraseError,
    SteganographyError,
    UnsupportedFormatError,
    UnsupportedVersionError,
)

__version__ = "1.0.0"

__all__ = [
    "ENCRYPTED_OVERHEAD",
    "HEADER_SIZE",
    "LOSSLESS_SUFFIXES",
    # format constants
    "MAGIC",
    "VERSION",
    "CapacityError",
    "FormatError",
    "ImageError",
    "PassphraseError",
    # exceptions
    "SteganographyError",
    "UnsupportedFormatError",
    "UnsupportedVersionError",
    "__version__",
    "capacity_bytes",
    # public API
    "embed",
    "embed_file",
    "extract",
    "extract_file",
    "load_image",
    "message_capacity",
]
