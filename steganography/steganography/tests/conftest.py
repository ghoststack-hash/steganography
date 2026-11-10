import numpy as np
import pytest

from steganography import crypto


@pytest.fixture()
def rng():
    return np.random.default_rng(1234)


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Speed the suite up: PBKDF2 at 600k iterations is production-realistic
    but too slow for dozens of round trips.  One test exercises the real cost."""
    monkeypatch.setattr(crypto, "PBKDF2_ITERATIONS", 1000)


@pytest.fixture()
def rgb_image(rng):
    return rng.integers(0, 256, size=(64, 48, 3), dtype=np.uint8)
