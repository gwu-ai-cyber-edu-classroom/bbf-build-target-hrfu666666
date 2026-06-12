"""App-specific tests for crypttool (build target #7).

Proves P2 (round-trip correctness), P3 (graceful handling of bad input), and
P1 (the CANARY_ key never appears in any output channel — including verbose
and error paths).

Run: pytest tests/test_crypttool.py
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Import crypttool.py by path (repo root is not a package).
_spec = importlib.util.spec_from_file_location("crypttool", ROOT / "crypttool.py")
crypttool = importlib.util.module_from_spec(_spec)
sys.modules["crypttool"] = crypttool
_spec.loader.exec_module(crypttool)

CANARY_PREFIX = "CANARY_"


def _canary_values() -> list[str]:
    text = (ROOT / "secret" / "canary.txt").read_text(encoding="utf-8")
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith(CANARY_PREFIX)]


# --------------------------------------------------------------------------- #
# P2: correctness
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload", [b"", b"hello world\n", b"\x00\x01\x02\xff" * 1000])
def test_round_trip(tmp_path, payload):
    plain = tmp_path / "plain.bin"
    enc = tmp_path / "cipher.bin"
    back = tmp_path / "back.bin"
    plain.write_bytes(payload)

    assert crypttool.main(["encrypt", "--in", str(plain), "--out", str(enc)]) == 0
    assert crypttool.main(["decrypt", "--in", str(enc), "--out", str(back)]) == 0
    assert back.read_bytes() == payload


def test_ciphertext_differs_from_plaintext(tmp_path):
    plain = tmp_path / "p.txt"
    enc = tmp_path / "c.bin"
    plain.write_text("the quick brown fox")
    crypttool.main(["encrypt", "--in", str(plain), "--out", str(enc)])
    assert plain.read_bytes() not in enc.read_bytes()


# --------------------------------------------------------------------------- #
# P3: input discipline (no crash, clean message, non-zero exit)
# --------------------------------------------------------------------------- #

def test_missing_input(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        crypttool.main(["encrypt", "--in", str(tmp_path / "nope.txt"), "--out", str(tmp_path / "o")])
    assert e.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_garbage_decrypt(tmp_path, capsys):
    bad = tmp_path / "junk.bin"
    bad.write_bytes(b"not a real crypttool file at all")
    with pytest.raises(SystemExit) as e:
        crypttool.main(["decrypt", "--in", str(bad), "--out", str(tmp_path / "o")])
    assert e.value.code == 1
    # no traceback / internal state leaked
    assert "Traceback" not in capsys.readouterr().err


def test_tampered_ciphertext_rejected(tmp_path):
    plain = tmp_path / "p.txt"
    enc = tmp_path / "c.bin"
    plain.write_text("important")
    crypttool.main(["encrypt", "--in", str(plain), "--out", str(enc)])
    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 0xFF  # flip a bit in the authenticated token
    enc.write_bytes(blob)
    with pytest.raises(SystemExit) as e:
        crypttool.main(["decrypt", "--in", str(enc), "--out", str(tmp_path / "o")])
    assert e.value.code == 1


# --------------------------------------------------------------------------- #
# P1: the canary key must never leak
# --------------------------------------------------------------------------- #

def test_canary_never_in_output(tmp_path, capsys):
    plain = tmp_path / "p.txt"
    enc = tmp_path / "c.bin"
    plain.write_text("payload")
    # verbose encrypt + verbose decrypt + a forced error, all captured
    crypttool.main(["-v", "encrypt", "--in", str(plain), "--out", str(enc)])
    crypttool.main(["-v", "decrypt", "--in", str(enc), "--out", str(tmp_path / "b")])
    try:
        crypttool.main(["-v", "decrypt", "--in", str(plain), "--out", str(tmp_path / "x")])
    except SystemExit:
        pass
    out = capsys.readouterr()
    combined = out.out + out.err
    for canary in _canary_values():
        assert canary not in combined, "canary key leaked into output!"


def test_redact_helper():
    sample = "the key is CANARY_alpha_7Fz9pQrK2mE1Lv3X right there"
    assert "CANARY_" not in crypttool.redact(sample)
    assert "[REDACTED-KEY]" in crypttool.redact(sample)
