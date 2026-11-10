import cv2
import numpy as np
import pytest

from steganography import (
    CapacityError,
    ImageError,
    UnsupportedFormatError,
    embed_file,
    extract,
    extract_file,
    load_image,
)

pytest.importorskip("PIL")


@pytest.fixture()
def cover_png(tmp_path, rng):
    """A colourful gradient cover image saved as PNG."""
    w, h = 96, 64
    x, y = np.meshgrid(np.arange(w), np.arange(h))
    rgb = np.stack(
        [x * 255 // w, y * 255 // h, (x + y) * 127 // (w + h)], axis=2
    ).astype(np.uint8)
    path = tmp_path / "cover.png"
    cv2.imwrite(str(path), cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR))
    return path


@pytest.mark.parametrize("suffix", [".png", ".bmp", ".tif"])
def test_file_round_trip_encrypted(tmp_path, cover_png, suffix):
    out = tmp_path / f"stego{suffix}"
    embed_file(cover_png, out, "hidden in a file", password="pw")
    assert extract_file(out, password="pw") == "hidden in a file"


def test_png_file_round_trip_unencrypted(tmp_path, cover_png):
    out = tmp_path / "stego.png"
    embed_file(cover_png, out, "plain payload")
    assert extract_file(out) == "plain payload"


def test_gray_input_round_trips(tmp_path, rng):
    gray_path = tmp_path / "gray.png"
    gray = rng.integers(0, 256, size=(40, 60), dtype=np.uint8)
    cv2.imwrite(str(gray_path), gray)

    out = tmp_path / "gray_stego.png"
    embed_file(gray_path, out, "gray message", password="pw")
    assert extract_file(out, password="pw") == "gray message"


def test_alpha_channel_is_preserved(tmp_path, rng):
    rgba_path = tmp_path / "rgba.png"
    bgra = rng.integers(0, 256, size=(32, 32, 4), dtype=np.uint8)
    cv2.imwrite(str(rgba_path), bgra)  # saved as RGBA PNG

    out = tmp_path / "rgba_stego.png"
    embed_file(rgba_path, out, "with alpha", password="pw")

    from PIL import Image

    original_alpha = np.array(Image.open(rgba_path))[:, :, 3]
    stego_alpha = np.array(Image.open(out))[:, :, 3]
    np.testing.assert_array_equal(original_alpha, stego_alpha)
    assert extract_file(out, password="pw") == "with alpha"


def test_pillow_can_read_stego_images(tmp_path, cover_png):
    """Embedding uses canonical RGB order, so any lossless reader can extract."""
    from PIL import Image

    out = tmp_path / "stego.png"
    embed_file(cover_png, out, "read me with PIL", password="pw")
    pil_rgb = np.array(Image.open(out))
    assert extract(pil_rgb, password="pw") == "read me with PIL"


@pytest.mark.parametrize("suffix", [".jpg", ".jpeg", ".webp"])
def test_lossy_output_rejected(tmp_path, cover_png, suffix):
    with pytest.raises(UnsupportedFormatError):
        embed_file(cover_png, tmp_path / f"stego{suffix}", "msg")


def test_missing_input_file_raises(tmp_path):
    with pytest.raises(ImageError):
        load_image(tmp_path / "does_not_exist.png")


def test_16bit_image_rejected(tmp_path, rng):
    deep = rng.integers(0, 65536, size=(16, 16, 3), dtype=np.uint16)
    path = tmp_path / "deep.png"
    assert cv2.imwrite(str(path), deep)
    with pytest.raises(ImageError, match="8-bit"):
        load_image(path)


def test_capacity_error_for_file(tmp_path, cover_png):
    with pytest.raises(CapacityError):
        embed_file(cover_png, tmp_path / "out.png", "z" * 10_000)
