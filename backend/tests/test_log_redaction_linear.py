"""Redacting a private-key block must cost the same on a log seeded with
unclosed BEGIN markers, which anyone can write there through a User-Agent."""
import time

from services.log_bundle import redact

KEY = ("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
       "-----END PRIVATE KEY-----")


def test_a_key_block_is_redacted_whole():
    text = f"before\n{KEY}\nafter"
    assert redact(text) == "before\n[redacted-private-key]\nafter"


def test_two_blocks_and_an_unclosed_marker():
    text = f"{KEY}\nnoise -----BEGIN RSA PRIVATE KEY----- alone\n{KEY}\n"
    out = redact(text)
    assert out.count("[redacted-private-key]") == 2
    assert "MIIEvQ" not in out


def test_a_seeded_log_is_redacted_in_linear_time():
    line = "2026-09-20 00:00:00 [api.scep_protocol] INFO SCEP request: ua='-----BEGIN PRIVATE KEY-----'\n"
    seeded = line * (1024 * 1024 // len(line))          # one megabyte of unclosed markers
    started = time.monotonic()
    out = redact(seeded)
    assert time.monotonic() - started < 1.5, "quadratic again"
    assert out.count("-----BEGIN PRIVATE KEY-----") == seeded.count("-----BEGIN PRIVATE KEY-----")
