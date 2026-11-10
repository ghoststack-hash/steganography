# Steganography

Secure data hiding inside images.  Messages are embedded into the least
significant bits of an image's colour channels and — unlike most hobby
tools — **encrypted with AES-256-GCM** under a key derived from your
passphrase, so the hidden data stays secret even if someone suspects a
message exists.

```
$ steganography embed -i cover.png -o stego.png -m "meet at noon" -p hunter2
$ steganography extract -i stego.png -p hunter2
meet at noon
```

## Features

- **Genuine LSB embedding** — every touched channel value changes by at
  most 1 (imperceptible).  The output is verified at PSNR > 50 dB.
- **Real cryptography** — AES-256-GCM authenticated encryption;
  PBKDF2-HMAC-SHA256 key derivation (600,000 iterations, 16-byte random
  salt).  Wrong passphrases are rejected reliably, not guessed.
- **Any length, any language** — a proper 12-byte header carries a
  uint32 length and a CRC-32; messages are UTF-8 (Chinese, emoji, …).
- **Lossless only** — PNG/BMP/TIFF output is enforced; saving to JPEG
  would silently destroy the payload, so it is rejected instead.
- **Library and CLI** — importable functions with a typed public API
  (`py.typed`), plus `steganography embed|extract|capacity` commands and
  the classic interactive menu.
- **Cross-library images** — bits are written in canonical RGB order, so
  stego images decode identically with OpenCV, Pillow or imageio.

## Install

Requires Python 3.10+.  Using [uv](https://docs.astral.sh/uv/):

```bash
uv sync                      # creates .venv and installs all dependencies
uv run steganography --help  # or: uv run pytest
```

Or with pip:

```bash
pip install -e .             # add --extra dev for pytest/pillow
```

> On headless servers you may swap `opencv-python` for
> `opencv-python-headless` — the API is identical.

## CLI usage

```bash
# Hide a message (encrypted)
steganography embed -i cover.png -o stego.png -m "the owl flies at midnight" -p hunter2

# Hide a message read from a file, passphrase typed interactively
steganography embed -i cover.png -o stego.png --message-file secret.txt --prompt-password

# Reveal it
steganography extract -i stego.png -p hunter2

# How much fits in an image?
steganography capacity -i cover.png
```

Running `steganography` with no arguments opens the interactive menu
(encrypt, extract, capacity — the original tool's workflow, hardened).

Exit codes: `0` success, `1` error (with a readable message on stderr),
`130` interrupted.

## Library usage

```python
from steganography import embed, extract, embed_file, extract_file

# Array level — the input array is never mutated
stego = embed(cover_rgb_array, "hello", password="hunter2")   # (H, W, 3) uint8
text  = extract(stego, password="hunter2")

# File level — grayscale and RGBA inputs are handled, alpha is preserved
embed_file("cover.png", "stego.png", "hello", password="hunter2")
extract_file("stego.png", password="hunter2")

# Capacity planning
from steganography import message_capacity, capacity_bytes
message_capacity(cover_rgb_array.shape, encrypted=True)  # bytes available
```

Errors are typed so callers can respond precisely:

```python
from steganography import FormatError, PassphraseError

try:
    extract_file("stego.png", password="hunter2")
except PassphraseError:
    ...  # wrong passphrase (or the payload was modified)
except FormatError:
    ...  # not a stego image / corrupted / unsupported version
```

## How it works

One payload bit is written into the least significant bit of each
colour-channel value, scanned in row-major order, most-significant bit
first per byte.  Each modified channel changes by ±1, which is far
below human (and typical statistical) perception for photographic
covers.

### Container format (version 2)

```
Offset  Size  Field
0       2     Magic bytes b"ST"
2       1     Format version (2)
3       1     Flags — bit 0: payload encrypted, bits 1-7 reserved
4       4     Payload length in bytes (uint32, big-endian)
8       4     CRC-32 of bytes 0-7 (uint32, big-endian)
12      N     Payload: ciphertext or raw UTF-8 message bytes
```

Encrypted payloads store `salt(16) || nonce(12) || ciphertext+tag(16)`,
so an encrypted message needs 44 bytes more capacity than its UTF-8
size.  The header's CRC-32 lets extraction distinguish *not a stego
image* from *corrupted image* from *wrong passphrase* (GCM tag failure).

### Capacity

| Image          | Plain text | Encrypted text |
| -------------- | ---------- | -------------- |
| 256 × 256 PNG  | 24,564 B   | 24,520 B       |
| 1024 × 768 PNG | 294,900 B  | 294,856 B      |
| 12 × 4 PNG     | 6 B        | 0 B            |

Formula: `(width × height × 3) // 8 - 12` bytes of container capacity;
subtract 44 more when encrypting.  Unused capacity is left untouched —
no tell-tale zero padding.

## Security notes and honest limitations

- **Confidentiality comes from the passphrase.**  LSB steganography
  alone is *not* encryption: without a passphrase the message is hidden
  but recoverable by anyone who knows the format.  The CLI prints a
  warning when you embed without one.
- **Detectability.**  Sequential-LSB embedding is detectable by
  statistical steganalysis (χ², RS analysis), especially on flat
  synthetic images.  This tool targets *invisibility to the eye* plus
  *cryptographic confidentiality* — not resistance to a determined
  steganalyst with the original cover for comparison.
- **The header is not encrypted** (magic, version, length).  An analyst
  can learn that *a* message exists and its length; they still cannot
  read or forge it.
- **Passphrase strength matters.**  PBKDF2 raises the cost of offline
  guessing ~600,000×, but `hunter2` is still `hunter2`.  Use long,
  random passphrases.
- **Integrity.**  GCM authentication detects any modification of the
  encrypted payload.  Unencrypted payloads have only the header CRC;
  their content is not tamper-protected.

## Development

```bash
uv sync --extra dev        # or: pip install -e . --extra dev
uv run pytest              # 63 tests: round trips, tampering, CLI, Pillow interop
uv run ruff check src tests
```

Project layout:

```
src/steganography/
├── core.py        # LSB engine, container format, file I/O
├── crypto.py      # AES-256-GCM + PBKDF2 payload protection
├── cli.py         # argparse commands + interactive menu
├── exceptions.py  # typed error hierarchy
└── py.typed
tests/             # pytest suite
```

## Migration from v0.x

Images written by the old prototype are **not readable**: the format is
incompatible (and was fundamentally broken — see `CHANGELOG.md`).
Re-embed any old messages with this version.

## License

MIT — see [LICENSE](LICENSE).
