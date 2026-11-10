import builtins
import getpass

import pytest

from steganography import cli


@pytest.fixture()
def cover_png(tmp_path):
    import numpy as np

    image = np.random.default_rng(7).integers(0, 256, size=(48, 64, 3), dtype=np.uint8)
    import cv2

    path = tmp_path / "cover.png"
    cv2.imwrite(str(path), image)
    return path


class Feed:
    """Replace input()/getpass() with a scripted list of answers (EOF at the end)."""

    def __init__(self, *answers):
        self.answers = list(answers)

    def __call__(self, prompt=""):
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


# ---------------------------------------------------------------------------
# Non-interactive commands
# ---------------------------------------------------------------------------

def test_embed_extract_round_trip(tmp_path, cover_png, capsys):
    stego = tmp_path / "stego.png"
    assert cli.main(["embed", "-i", str(cover_png), "-o", str(stego),
                     "-m", "cli secret", "-p", "pw"]) == 0
    assert cli.main(["extract", "-i", str(stego), "-p", "pw"]) == 0
    assert "cli secret" in capsys.readouterr().out


def test_embed_without_password_warns(tmp_path, cover_png, capsys):
    stego = tmp_path / "stego.png"
    assert cli.main(["embed", "-i", str(cover_png), "-o", str(stego), "-m", "x"]) == 0
    assert "NOT encrypted" in capsys.readouterr().err


def test_extract_without_password_on_encrypted_image_fails(tmp_path, cover_png, capsys):
    stego = tmp_path / "stego.png"
    cli.main(["embed", "-i", str(cover_png), "-o", str(stego), "-m", "x", "-p", "pw"])
    capsys.readouterr()
    code = cli.main(["extract", "-i", str(stego)])
    assert code == 1
    assert "passphrase" in capsys.readouterr().err.lower()


def test_message_from_file(tmp_path, cover_png, capsys):
    message_file = tmp_path / "msg.txt"
    message_file.write_text("from a file", encoding="utf-8")
    stego = tmp_path / "stego.png"
    cli.main(["embed", "-i", str(cover_png), "-o", str(stego),
              "--message-file", str(message_file)])
    cli.main(["extract", "-i", str(stego)])
    assert "from a file" in capsys.readouterr().out


def test_capacity_command(tmp_path, cover_png, capsys):
    assert cli.main(["capacity", "-i", str(cover_png)]) == 0
    out = capsys.readouterr().out
    assert "Container capacity" in out
    assert "Max message (AES)" in out


def test_error_exits_nonzero(tmp_path, capsys):
    assert cli.main(["extract", "-i", str(tmp_path / "missing.png")]) == 1
    assert "could not read image" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    assert "steganography" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def test_interactive_full_flow(tmp_path, cover_png, capsys, monkeypatch):
    stego_default = cover_png.with_suffix(".stego.png")
    inputs = Feed(
        "1",                # menu: embed
        str(cover_png),     # cover path
        "interactive secret",  # message
        "",                 # output path -> default .stego.png
        "2",                # menu: extract
        str(stego_default),  # stego path
        "",                 # passphrase (wrongly empty first)
        "menu-pw",          # passphrase retry
        "q",                # quit
    )
    passwords = Feed("", "menu-pw")  # getpass answers in call order

    monkeypatch.setattr(builtins, "input", inputs)
    monkeypatch.setattr(getpass, "getpass", passwords)

    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "interactive secret" in out
    assert stego_default.is_file()


def test_interactive_capacity(tmp_path, cover_png, capsys, monkeypatch):
    monkeypatch.setattr(builtins, "input", Feed("3", str(cover_png), "q"))
    assert cli.main([]) == 0
    assert "Container capacity" in capsys.readouterr().out


def test_interactive_invalid_choice_then_quit(monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", Feed("9", "nope", "q"))
    assert cli.main([]) == 0
    assert "Invalid choice." in capsys.readouterr().out


def test_interactive_error_is_reported_not_raised(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(builtins, "input", Feed("2", str(tmp_path / "ghost.png"), "q"))
    assert cli.main([]) == 0  # loops instead of crashing


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

def test_steganography_error_is_catchable():
    assert issubclass(cli.SteganographyError, Exception)


def test_package_exports_version():
    import steganography

    assert steganography.__version__
