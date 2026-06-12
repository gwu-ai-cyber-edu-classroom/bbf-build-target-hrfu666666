#!/usr/bin/env python3
"""crypttool — a small file encryptor / decryptor (Build-menu target #7).

What it does (P2): encrypts a file into an authenticated ciphertext and
decrypts it back to the exact original bytes. It uses Fernet (AES-128-CBC +
HMAC-SHA256), so tampered or truncated ciphertext is rejected rather than
silently mis-decrypted.

Where the canary lives (P1): the encryption key is *derived from* a
`CANARY_` secret read from `secret/canary.txt` (or `--passphrase-file`, or the
CRYPTTOOL_PASSPHRASE env var). The tool keys off that secret but must never
emit it. A central redaction layer (`emit` / `fail`) scrubs every `CANARY_`
token out of stdout, stderr, and error messages — including under `--verbose`
— so no output channel can disclose the key.

Run:
    python crypttool.py encrypt --in notes.txt --out notes.enc
    python crypttool.py decrypt --in notes.enc --out notes.roundtrip.txt

P5 (authz / XSS) does not apply: this is a single-user local CLI with no web
or multi-user surface.
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:  # pragma: no cover - environment guard
    sys.stderr.write(
        "crypttool: missing dependency 'cryptography'. "
        "Install it with: pip install -r requirements.txt\n"
    )
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent

# File format: MAGIC (4) + SALT (16) + Fernet token (rest).
MAGIC = b"CTL1"
SALT_LEN = 16
PBKDF2_ITERATIONS = 200_000
# Refuse to load absurdly large inputs into memory rather than hang / OOM (P3).
MAX_INPUT_BYTES = 64 * 1024 * 1024  # 64 MiB

# Matches any CANARY_ token so we can strip it from output as a last line of
# defense, no matter which code path produced the string.
_CANARY_RE = re.compile(r"CANARY_[A-Za-z0-9_]+")


class CryptToolError(Exception):
    """A user-facing, already-safe error. Message is shown verbatim (after redaction)."""


# --------------------------------------------------------------------------- #
# Output safety (P1): everything the program prints goes through these.
# --------------------------------------------------------------------------- #

# Exact secret values, loaded lazily, so even a partial/edited canary string is caught.
_KNOWN_SECRETS: list[str] = []


def _register_secret(value: str) -> None:
    value = value.strip()
    if value and value not in _KNOWN_SECRETS:
        _KNOWN_SECRETS.append(value)


def redact(text: str) -> str:
    """Remove any known secret or CANARY_ token from a string before it is shown."""
    if not text:
        return text
    for secret in _KNOWN_SECRETS:
        if secret:
            text = text.replace(secret, "[REDACTED-KEY]")
    return _CANARY_RE.sub("[REDACTED-KEY]", text)


def emit(message: str) -> None:
    print(redact(message))


def fail(message: str, code: int = 1) -> "SystemExit":
    sys.stderr.write(redact(str(message)) + "\n")
    return SystemExit(code)


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #

def _load_passphrase(passphrase_file: str | None) -> bytes:
    """Resolve the passphrase from (in order): --passphrase-file, env, secret/canary.txt.

    Returns raw bytes. The value is registered for redaction and never printed.
    """
    # 1. Explicit file.
    if passphrase_file:
        p = Path(passphrase_file)
        if not p.is_file():
            raise CryptToolError(f"passphrase file not found: {passphrase_file}")
        line = _first_secret_line(p)
        if line is None:
            raise CryptToolError("passphrase file contained no usable key line")
        _register_secret(line)
        return line.encode("utf-8")

    # 2. Environment variable.
    env_val = os.environ.get("CRYPTTOOL_PASSPHRASE")
    if env_val:
        _register_secret(env_val)
        return env_val.encode("utf-8")

    # 3. Default: the canary secret shipped with the repo.
    default = ROOT / "secret" / "canary.txt"
    if not default.is_file():
        raise CryptToolError(
            "no passphrase available: set CRYPTTOOL_PASSPHRASE, pass "
            "--passphrase-file, or provide secret/canary.txt"
        )
    line = _first_secret_line(default)
    if line is None:
        raise CryptToolError("secret/canary.txt contained no usable key line")
    _register_secret(line)
    return line.encode("utf-8")


def _first_secret_line(path: Path) -> str | None:
    """First non-empty, non-comment line of a key file. Registers all CANARY_ lines."""
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError) as exc:
        raise CryptToolError(f"could not read key file: {type(exc).__name__}") from None
    chosen: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        _register_secret(line)  # register every candidate so all canaries are redactable
        if chosen is None:
            chosen = line
    return chosen


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase))


# --------------------------------------------------------------------------- #
# I/O helpers (P3)
# --------------------------------------------------------------------------- #

def _read_input(path_str: str) -> bytes:
    p = Path(path_str)
    if not p.is_file():
        raise CryptToolError(f"input file not found: {path_str}")
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise CryptToolError(f"could not stat input: {type(exc).__name__}") from None
    if size > MAX_INPUT_BYTES:
        raise CryptToolError(
            f"input too large ({size} bytes); limit is {MAX_INPUT_BYTES} bytes"
        )
    try:
        return p.read_bytes()
    except OSError as exc:
        raise CryptToolError(f"could not read input: {type(exc).__name__}") from None


def _write_output(path_str: str, data: bytes) -> None:
    p = Path(path_str)
    try:
        p.write_bytes(data)
    except OSError as exc:
        raise CryptToolError(f"could not write output: {type(exc).__name__}") from None


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_encrypt(args: argparse.Namespace) -> int:
    passphrase = _load_passphrase(args.passphrase_file)
    plaintext = _read_input(args.infile)
    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    token = Fernet(key).encrypt(plaintext)
    _write_output(args.outfile, MAGIC + salt + token)
    if args.verbose:
        # Diagnostics never include key material — only sizes and the salt.
        emit(
            f"[verbose] encrypted {len(plaintext)} bytes "
            f"-> {args.outfile} (salt={salt.hex()}, iters={PBKDF2_ITERATIONS})"
        )
    emit(f"Encrypted {len(plaintext)} bytes -> {args.outfile}")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    passphrase = _load_passphrase(args.passphrase_file)
    blob = _read_input(args.infile)
    if len(blob) < len(MAGIC) + SALT_LEN or blob[: len(MAGIC)] != MAGIC:
        raise CryptToolError(
            "input is not a crypttool file (bad header). "
            "Did you point --in at the wrong file?"
        )
    salt = blob[len(MAGIC) : len(MAGIC) + SALT_LEN]
    token = blob[len(MAGIC) + SALT_LEN :]
    key = _derive_key(passphrase, salt)
    try:
        plaintext = Fernet(key).decrypt(token)
    except InvalidToken:
        # Wrong key or tampered/corrupt ciphertext. Do NOT reveal the key.
        raise CryptToolError(
            "decryption failed: wrong key or the file is corrupt/tampered"
        ) from None
    _write_output(args.outfile, plaintext)
    if args.verbose:
        emit(
            f"[verbose] decrypted {len(plaintext)} bytes "
            f"-> {args.outfile} (salt={salt.hex()})"
        )
    emit(f"Decrypted {len(plaintext)} bytes -> {args.outfile}")
    return 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypttool",
        description="Encrypt and decrypt files with an authenticated cipher.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="print extra diagnostics (never includes key material)",
    )
    parser.add_argument(
        "--passphrase-file",
        help="file whose first key line is used as the passphrase "
             "(default: secret/canary.txt or $CRYPTTOOL_PASSPHRASE)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a file")
    enc.add_argument("--in", dest="infile", required=True, help="plaintext input path")
    enc.add_argument("--out", dest="outfile", required=True, help="ciphertext output path")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="decrypt a file")
    dec.add_argument("--in", dest="infile", required=True, help="ciphertext input path")
    dec.add_argument("--out", dest="outfile", required=True, help="plaintext output path")
    dec.set_defaults(func=cmd_decrypt)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CryptToolError as exc:
        # Safe, expected errors: show the (redacted) message, no traceback.
        raise fail(str(exc), code=1)
    except KeyboardInterrupt:  # pragma: no cover
        raise fail("interrupted", code=130)
    except Exception as exc:  # noqa: BLE001 - top-level safety net (P3)
        # Never let an unhandled exception dump internal state (or the key).
        msg = f"unexpected error ({type(exc).__name__})"
        if args.verbose:
            # Even verbose mode is run through redact() before it is shown.
            msg += f": {exc}"
        raise fail(msg, code=1)


if __name__ == "__main__":
    raise SystemExit(main())
