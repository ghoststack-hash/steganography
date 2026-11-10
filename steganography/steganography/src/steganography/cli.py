"""Command-line and interactive interface for steganography."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__, core
from .exceptions import PassphraseError, SteganographyError

__all__ = ["build_parser", "main"]


# ---------------------------------------------------------------------------
# Shared argument resolution
# ---------------------------------------------------------------------------

def _resolve_message(args: argparse.Namespace) -> str:
    if args.message is not None:
        return args.message
    if args.message_file is not None:
        try:
            if args.message_file == "-":
                return sys.stdin.read()
            return Path(args.message_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise SteganographyError(f"cannot read message file: {exc}") from exc
    return input("Message to hide: ")


def _resolve_password(args: argparse.Namespace) -> str | None:
    if args.prompt_password:
        password = getpass.getpass("Passphrase (empty to store unencrypted): ")
        if not password:
            return None
        return password
    if args.password is not None:
        if not args.password:
            raise SteganographyError(
                "passphrase must not be empty; omit -p/--password to store unencrypted"
            )
        return args.password
    return None


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_embed(args: argparse.Namespace) -> int:
    message = _resolve_message(args)
    password = _resolve_password(args)
    if password is None:
        print("Note: no passphrase given — the message is hidden but NOT encrypted.", file=sys.stderr)
    core.embed_file(args.image, args.out, message, password=password)
    print(f"Message embedded -> {args.out}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    password = _resolve_password(args)
    try:
        message = core.extract_file(args.image, password=password)
    except PassphraseError:
        # If the caller simply did not know a passphrase was needed, offer
        # one interactive retry before failing.
        if password is None and not args.prompt_password and sys.stdin.isatty():
            password = getpass.getpass("Passphrase: ")
            message = core.extract_file(args.image, password=password)
        else:
            raise
    print(message)
    return 0


def cmd_capacity(args: argparse.Namespace) -> int:
    image = core.load_image(args.image)
    shape = image.shape
    print(f"Image:                {args.image} ({shape[0]}x{shape[1]})")
    print(f"Container capacity:   {core.capacity_bytes(shape)} bytes (header included)")
    print(f"Max message (plain):  {core.message_capacity(shape)} bytes")
    print(
        f"Max message (AES):    {core.message_capacity(shape, encrypted=True)} bytes "
        f"({core.ENCRYPTED_OVERHEAD} bytes encryption overhead)"
    )
    return 0


# ---------------------------------------------------------------------------
# Interactive mode (kept for parity with the original tool)
# ---------------------------------------------------------------------------

def _ask_path(prompt: str) -> str:
    while True:
        raw = input(prompt).strip()
        if not raw:
            print("Please enter a file path.")
            continue
        if not Path(raw).is_file():
            print(f"No such file: {raw}")
            continue
        return raw


def _interactive_embed() -> None:
    src = _ask_path("Cover image path: ")
    message = ""
    while not message:
        message = input("Message to hide: ")
    password = getpass.getpass("Passphrase (empty = no encryption): ") or None
    default_out = str(Path(src).with_suffix(".stego.png"))
    out = input(f"Output image [{default_out}]: ").strip() or default_out
    core.embed_file(src, out, message, password=password)
    print(f"Done — message written to {out}")


def _interactive_extract() -> None:
    src = _ask_path("Stego image path: ")
    password = getpass.getpass("Passphrase (empty if not encrypted): ") or None
    try:
        message = core.extract_file(src, password=password)
    except PassphraseError:
        if password is None:
            password = getpass.getpass("A passphrase is required: ")
            message = core.extract_file(src, password=password)
        else:
            raise
    print(f"Hidden message: {message}")


def _interactive_capacity() -> None:
    src = _ask_path("Image path: ")
    shape = core.load_image(src).shape
    print(f"Container capacity:  {core.capacity_bytes(shape)} bytes")
    print(f"Max message (plain): {core.message_capacity(shape)} bytes")
    print(f"Max message (AES):   {core.message_capacity(shape, encrypted=True)} bytes")


def _interactive() -> int:
    print(f"steganography {__version__} — hide secret messages inside images")
    while True:
        print()
        print("  1) Hide a message in an image")
        print("  2) Reveal a hidden message")
        print("  3) Show an image's capacity")
        print("  q) Quit")
        choice = input("Choose an option: ").strip().lower()
        try:
            if choice == "1":
                _interactive_embed()
            elif choice == "2":
                _interactive_extract()
            elif choice == "3":
                _interactive_capacity()
            elif choice in {"q", "quit", "exit"}:
                return 0
            else:
                print("Invalid choice.")
        except SteganographyError as exc:
            print(f"Error: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="steganography",
        description="Hide secret messages inside images using LSB steganography.",
    )
    parser.add_argument("--version", action="version", version=f"steganography {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    p_embed = sub.add_parser("embed", help="hide a message in an image")
    p_embed.add_argument("-i", "--image", required=True, help="cover image (input)")
    p_embed.add_argument("-o", "--out", required=True, help="output image (PNG/BMP/TIFF)")
    p_embed.add_argument("-m", "--message", help="message to hide")
    p_embed.add_argument(
        "--message-file", help="read the message from a file ('-' for standard input)"
    )
    p_embed.add_argument(
        "-p", "--password", help="passphrase (enables AES-256-GCM encryption)"
    )
    p_embed.add_argument(
        "--prompt-password", action="store_true", help="ask for the passphrase interactively"
    )
    p_embed.set_defaults(func=cmd_embed)

    p_extract = sub.add_parser("extract", help="reveal a hidden message")
    p_extract.add_argument("-i", "--image", required=True, help="stego image (input)")
    p_extract.add_argument(
        "-p", "--password", help="passphrase (if the message was encrypted)"
    )
    p_extract.add_argument(
        "--prompt-password", action="store_true", help="ask for the passphrase interactively"
    )
    p_extract.set_defaults(func=cmd_extract)

    p_cap = sub.add_parser("capacity", help="show how much data an image can hold")
    p_cap.add_argument("-i", "--image", required=True, help="image to inspect")
    p_cap.set_defaults(func=cmd_capacity)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  With no arguments an interactive menu is shown."""
    args_list = sys.argv[1:] if argv is None else list(argv)
    if not args_list:
        try:
            return _interactive()
        except (KeyboardInterrupt, EOFError):
            print()
            return 0

    args = build_parser().parse_args(args_list)
    try:
        return int(args.func(args))
    except SteganographyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
