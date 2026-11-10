# Changelog

## 1.0.0 — rewrite

The library was rewritten from the ground up.  Images produced by the
previous prototype (v0.x) are **not readable** by this version.

### Security

- Message payloads are now encrypted with AES-256-GCM (authenticated
  encryption) under a key derived from the passphrase with
  PBKDF2-HMAC-SHA256 (16-byte random salt, 600,000 iterations).
  Previously only the *first character* of the passphrase was compared,
  and the message itself was stored as plain text in the pixels.
- The passphrase is never stored in the image; only the random salt is.
- Wrong passphrases are now detected reliably (GCM tag verification)
  instead of being guessed from a single stored character.

### Correctness

- Messages of any length are supported via a proper 12-byte header
  (magic, version, flags, uint32 length, CRC-32) — the old code stored
  the length in a single byte, so anything longer than 255 characters
  silently wrapped or crashed with `OverflowError`.
- Full Unicode support (UTF-8).  The old code crashed on any character
  outside Latin-1 (e.g. Chinese text or emoji).
- Genuine LSB embedding: each channel value changes by at most 1.
  The old code *replaced* whole channel bytes, visibly repainting pixels.
- Lossy output formats (JPEG, WebP) are rejected instead of silently
  destroying the payload.
- Grayscale and RGBA images are handled; alpha channels are preserved.
- Extraction distinguishes "not a stego image", "corrupted image" and
  "wrong passphrase" via CRC-32 and GCM authentication.

### API & tooling

- Proper package layout (`core`, `crypto`, `cli`, `exceptions`) with type
  hints, docstrings and a typed public API (`py.typed`).
- The library is importable: `embed`/`extract` operate on arrays,
  `embed_file`/`extract_file` on files.  No more mandatory `input()`.
- New CLI subcommands: `steganography embed|extract|capacity` (plus the
  original interactive menu when run without arguments).
- Full pytest suite covering round trips, tampering, capacity limits,
  file formats, CLI and an interoperability check against Pillow.
