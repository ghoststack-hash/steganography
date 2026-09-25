# Steganography

Secure data hiding inside images using LSB (Least Significant Bit) modification with built-in passcode protection.

## Features

- **Invisible Embedding:** Hides messages in pixel data with zero visible degradation.
- **Passcode Protection:** Restricts extraction to authorized passcode holders.
- **Lightweight:** Built on standard image processing libraries with minimal overhead.
- **Lossless Storage:** Generates pixel-accurate output using PNG format.

---

## Tech Stack

- **Python 3.x**
- `opencv-python` (`cv2`) – Image I/O and matrix operations
- `numpy` – Fast pixel array manipulations
- `os` – System viewer integration
- `uv` - Package manager

---

## Quickstart

### 1. Installation

```bash
uv add opencv-python numpy
