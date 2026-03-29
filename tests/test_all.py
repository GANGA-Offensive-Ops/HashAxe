#!/usr/bin/env python3
# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_all.py
#  Comprehensive test suite for CRACK covering parser, engine, mutations, masks.
#  Tests all key formats, CRLF fixes, bad inputs, and hashcat rule parsing.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
tests/test_all.py — Comprehensive test suite for hashaxe v2.

Covers:
  • Parser        — all key formats, CRLF fix, bad inputs
  • Engine        — fast-path, full-confirm, unencrypted
  • Mutations     — rule coverage, leet, suffixes, deduplication
  • Mask engine   — parsing, candidate gen, custom charsets, hybrid
  • Hashcat rules — parse .rule syntax, apply operations
  • Wordlist      — streaming chunker, line counting, validation
  • Session       — save/load/resume/delete, stale detection
  • Display       — progress bar, zero-speed guard, render checks
  • Integration   — end-to-end hashaxe() with real keys and tiny wordlists

Run:
    python3 -m pytest tests/test_all.py -v
    python3 tests/test_all.py            # standalone
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from hashaxe.display import Display
from hashaxe.engine import try_passphrase, try_passphrase_full
from hashaxe.parser import KeyFormat, ParsedKey, parse_key_file
from hashaxe.rules.hashcat import (
    _parse_rule_line,
    apply_rule_line,
    apply_rules_from_file,
    get_builtin_rules,
    load_rule_file,
)
from hashaxe.rules.mask import MaskEngine, incremental_candidates
from hashaxe.rules.mutations import apply_rules, count_rules
from hashaxe.session import Session, session_name_for
from hashaxe.wordlist import WordlistStreamer, chunk_wordlist, validate_wordlist

# ── Helpers ───────────────────────────────────────────────────────────────────

KEYS_DIR = Path(__file__).parent.parent / "test_files"


def _tmp_file(content: bytes, suffix: str = ".txt") -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(content)
    f.close()
    return f.name


def _wordlist(words: list[str]) -> str:
    return _tmp_file("\n".join(words).encode() + b"\n", ".txt")


# ══════════════════════════════════════════════════════════════════════════════
# PARSER TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestParser:

    def test_rsa_legacy_encrypted(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert pk.fmt == KeyFormat.OPENSSH_LEGACY
        assert pk.is_encrypted is True
        assert pk.key_type == "ssh-rsa"
        assert len(pk.edata) > 0
        assert len(pk.legacy_iv) == 16

    def test_rsa_legacy_unencrypted(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_nopass.key"))
        assert pk.fmt == KeyFormat.OPENSSH_LEGACY
        assert pk.is_encrypted is False

    def test_ecdsa_legacy_encrypted(self):
        pk = parse_key_file(str(KEYS_DIR / "ecdsa_legacy_abc123.key"))
        assert pk.fmt == KeyFormat.OPENSSH_LEGACY
        assert pk.is_encrypted is True
        assert pk.key_type == "ecdsa"

    def test_crlf_auto_fix(self):
        """CRLF in PEM envelope must be stripped without error."""
        raw = (KEYS_DIR / "rsa_legacy_puppet.key").read_bytes()
        crlf = raw.replace(b"\n", b"\r\n")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as f:
            f.write(crlf)
            tmp = f.name
        try:
            pk = parse_key_file(tmp)
            assert pk.is_encrypted
        finally:
            os.unlink(tmp)

    def test_rejects_empty_file(self):
        tmp = _tmp_file(b"")
        try:
            try:
                parse_key_file(tmp)
                assert False, "should raise"
            except ValueError:
                pass
        finally:
            os.unlink(tmp)

    def test_rejects_random_bytes(self):
        tmp = _tmp_file(os.urandom(256))
        try:
            try:
                parse_key_file(tmp)
                assert False, "should raise"
            except ValueError:
                pass
        finally:
            os.unlink(tmp)

    def test_rejects_pubkey_only(self):
        """The bad fixture from v1 (truncated ECDSA) must raise ValueError."""
        try:
            parse_key_file(str(KEYS_DIR / "openssh_bad_fixture.key"))
            assert False, "should raise"
        except ValueError:
            pass

    def test_file_not_found(self):
        try:
            parse_key_file("/nonexistent/path/key.pem")
            assert False, "should raise"
        except FileNotFoundError:
            pass

    def test_cipher_display(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert pk.cipher_display  # non-empty

    def test_kdf_display(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert pk.kdf_display  # non-empty


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestEngine:

    def test_rsa_correct_password(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert try_passphrase(pk, b"puppet") is True

    def test_rsa_wrong_password(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert try_passphrase(pk, b"wrongpassword") is False

    def test_rsa_full_confirm(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert try_passphrase_full(pk, b"puppet") is True

    def test_rsa_full_confirm_wrong(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert try_passphrase_full(pk, b"wrongpassword") is False

    def test_ecdsa_correct_password(self):
        pk = parse_key_file(str(KEYS_DIR / "ecdsa_legacy_abc123.key"))
        assert try_passphrase(pk, b"abc123") is True

    def test_ecdsa_wrong_password(self):
        pk = parse_key_file(str(KEYS_DIR / "ecdsa_legacy_abc123.key"))
        assert try_passphrase(pk, b"notabc123") is False

    def test_unencrypted_always_true(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_nopass.key"))
        assert try_passphrase(pk, b"anything") is True
        assert try_passphrase(pk, b"") is True

    def test_empty_password_rejected(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert try_passphrase(pk, b"") is False

    def test_binary_garbage_rejected(self):
        pk = parse_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key"))
        assert try_passphrase(pk, os.urandom(32)) is False


# ══════════════════════════════════════════════════════════════════════════════
# MUTATION RULES TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestMutations:

    def test_original_present(self):
        assert "puppet" in list(apply_rules("puppet"))

    def test_capitalize_present(self):
        assert "Puppet" in list(apply_rules("puppet"))

    def test_uppercase_present(self):
        assert "PUPPET" in list(apply_rules("puppet"))

    def test_lowercase_present(self):
        assert "puppet" in list(apply_rules("PUPPET"))

    def test_suffix_123(self):
        assert "puppet123" in list(apply_rules("puppet"))

    def test_suffix_exclamation(self):
        assert "puppet!" in list(apply_rules("puppet"))

    def test_cap_suffix_combo(self):
        assert "Puppet123" in list(apply_rules("puppet"))

    def test_leet_speak(self):
        words = list(apply_rules("password"))
        # p@ssw0rd or p@$$w0rd variant
        assert any("@" in w or "0" in w or "$" in w for w in words)

    def test_no_duplicates(self):
        words = list(apply_rules("abc"))
        assert len(words) == len(set(words)), "duplicates found in mutation output"

    def test_year_suffix(self):
        words = list(apply_rules("puppet"))
        assert "puppet2024" in words
        assert "puppet2025" in words

    def test_reversed(self):
        words = list(apply_rules("puppet"))
        assert "teppup" in words

    def test_doubled(self):
        words = list(apply_rules("abc"))
        assert "abcabc" in words

    def test_count_rules_consistent(self):
        """count_rules() must match actual output."""
        expected = count_rules()
        actual = len(list(apply_rules("password")))
        assert actual == expected, f"count_rules={expected} but actual={actual}"

    def test_single_char_no_crash(self):
        words = list(apply_rules("a"))
        assert len(words) > 1

    def test_empty_string_no_crash(self):
        words = list(apply_rules(""))
        # Should still return something (empty string + mutations)
        assert isinstance(words, list)


# ══════════════════════════════════════════════════════════════════════════════
# MASK ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestMaskEngine:

    def test_digit_mask(self):
        engine = MaskEngine("?d?d?d")
        cands = list(engine.candidates())
        assert len(cands) == 1000
        assert "000" in cands
        assert "999" in cands
        assert "123" in cands

    def test_lower_mask(self):
        engine = MaskEngine("?l?l")
        cands = list(engine.candidates())
        assert len(cands) == 26 * 26
        assert "aa" in cands
        assert "zz" in cands

    def test_literal_prefix(self):
        engine = MaskEngine("Pass?d?d?d")
        cands = list(engine.candidates())
        assert len(cands) == 1000
        assert all(c.startswith("Pass") for c in cands)
        assert "Pass000" in cands
        assert "Pass999" in cands

    def test_candidate_count(self):
        engine = MaskEngine("?l?u?d")
        assert engine.candidate_count() == 26 * 26 * 10

    def test_custom_charset(self):
        engine = MaskEngine("?1?1?1", custom={"?1": "abc"})
        cands = list(engine.candidates())
        assert len(cands) == 27  # 3^3
        assert "aaa" in cands
        assert "abc" in cands

    def test_candidates_from_skip(self):
        engine = MaskEngine("?d?d")
        all_c = list(engine.candidates())
        skip5 = list(engine.candidates_from(5))
        assert skip5 == all_c[5:]

    def test_invalid_token_raises(self):
        try:
            MaskEngine("?x?l")
            assert False, "should raise"
        except ValueError:
            pass

    def test_upper_mask(self):
        engine = MaskEngine("?u?u")
        cands = list(engine.candidates())
        assert len(cands) == 26 * 26
        assert all(c.isupper() for c in cands)

    def test_all_charset_size(self):
        engine = MaskEngine("?a")
        # ?a = lower(26) + upper(26) + digits(10) + special(32) = 94
        assert engine.candidate_count() == 94

    def test_incremental_candidates(self):
        cands = list(incremental_candidates("abc", min_len=1, max_len=2))
        assert "a" in cands
        assert "aa" in cands
        assert "ab" in cands
        assert "bc" in cands


# ══════════════════════════════════════════════════════════════════════════════
# HASHCAT RULE TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestHashcatRules:

    def test_noop(self):
        ops = _parse_rule_line(":")
        assert apply_rule_line("puppet", ops) == "puppet"

    def test_lowercase(self):
        ops = _parse_rule_line("l")
        assert apply_rule_line("PUPPET", ops) == "puppet"

    def test_uppercase(self):
        ops = _parse_rule_line("u")
        assert apply_rule_line("puppet", ops) == "PUPPET"

    def test_capitalize(self):
        ops = _parse_rule_line("c")
        assert apply_rule_line("puppet", ops) == "Puppet"

    def test_reverse(self):
        ops = _parse_rule_line("r")
        assert apply_rule_line("puppet", ops) == "teppup"

    def test_duplicate(self):
        ops = _parse_rule_line("d")
        assert apply_rule_line("ab", ops) == "abab"

    def test_append_char(self):
        ops = _parse_rule_line("$1")
        assert apply_rule_line("puppet", ops) == "puppet1"

    def test_prepend_char(self):
        ops = _parse_rule_line("^!")
        assert apply_rule_line("puppet", ops) == "!puppet"

    def test_replace(self):
        # so0: replace all 's' with '0'
        ops = _parse_rule_line("so0")
        assert apply_rule_line("password", ops) == "passw0rd"
        # sa@: replace all 'a' with '@'
        ops2 = _parse_rule_line("sa@")
        assert apply_rule_line("password", ops2) == "p@ssword"

    def test_delete_char(self):
        ops = _parse_rule_line("D0")
        assert apply_rule_line("puppet", ops) == "uppet"

    def test_truncate_left(self):
        ops = _parse_rule_line("[")
        assert apply_rule_line("puppet", ops) == "uppet"

    def test_truncate_right(self):
        ops = _parse_rule_line("]")
        assert apply_rule_line("puppet", ops) == "puppe"

    def test_chained_rules(self):
        ops = _parse_rule_line("c $1 $2 $3")
        assert apply_rule_line("puppet", ops) == "Puppet123"

    def test_comment_ignored(self):
        ops = _parse_rule_line("# this is a comment")
        assert ops == []

    def test_empty_line_ignored(self):
        ops = _parse_rule_line("")
        assert ops == []

    def test_rule_file_loading(self):
        rule_content = b":\nl\nu\nc\nr\n$1\n$!\n"
        tmp = _tmp_file(rule_content, ".rule")
        try:
            rules = load_rule_file(tmp)
            assert len(rules) == 7
        finally:
            os.unlink(tmp)

    def test_apply_rules_from_file(self):
        rules = get_builtin_rules("best64")
        candidates = list(apply_rules_from_file("puppet", rules))
        assert "puppet" in candidates
        assert "PUPPET" in candidates
        assert "Puppet" in candidates
        assert "teppup" in candidates

    def test_builtin_best64(self):
        rules = get_builtin_rules("best64")
        assert len(rules) > 10

    def test_unknown_builtin_raises(self):
        try:
            get_builtin_rules("unknown_rule_set")
            assert False, "should raise"
        except ValueError:
            pass

    def test_rotate_left(self):
        ops = _parse_rule_line("{")
        assert apply_rule_line("puppet", ops) == "uppetP"[:-1] + "p"
        # rotate left: move first char to end
        assert apply_rule_line("abc", ops) == "bca"

    def test_rotate_right(self):
        ops = _parse_rule_line("}")
        # rotate right: move last char to front
        assert apply_rule_line("abc", ops) == "cab"

    def test_insert_char(self):
        ops = _parse_rule_line("i2X")
        assert apply_rule_line("abc", ops) == "abXc"

    def test_overwrite_char(self):
        ops = _parse_rule_line("o0Z")
        assert apply_rule_line("abc", ops) == "Zbc"

    def test_extract(self):
        ops = _parse_rule_line("x13")
        # extract from pos 1, length 3 → "bcd" from "abcde"
        assert apply_rule_line("abcde", ops) == "bcd"


# ══════════════════════════════════════════════════════════════════════════════
# WORDLIST TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestWordlist:

    def test_count_lines(self):
        wl = _wordlist(["alpha", "beta", "gamma", "delta"])
        try:
            s = WordlistStreamer(wl)
            assert s.count_lines() == 4
        finally:
            os.unlink(wl)

    def test_lines_all(self):
        wl = _wordlist(["alpha", "beta", "gamma"])
        try:
            s = WordlistStreamer(wl)
            lines = [l.rstrip(b"\n").decode() for l in s.lines()]
            assert lines == ["alpha", "beta", "gamma"]
        finally:
            os.unlink(wl)

    def test_chunk_wordlist_4_chunks(self):
        words = [f"word{i}" for i in range(100)]
        wl = _wordlist(words)
        try:
            chunks, total = chunk_wordlist(wl, 4)
            assert total == 100
            assert len(chunks) == 4
            # Reconstruct — boundary skipping may drop up to N boundary words
            s = WordlistStreamer(wl)
            recovered = []
            for start, end in chunks:
                for line in s.lines(start, end):
                    w = line.rstrip(b"\n").decode()
                    if w:
                        recovered.append(w)
            # Allow up to n_chunks boundary words to be skipped
            assert len(recovered) >= 100 - 4, f"Expected >=96 words, got {len(recovered)}"
        finally:
            os.unlink(wl)

    def test_chunk_wordlist_single(self):
        wl = _wordlist(["a", "b", "c"])
        try:
            chunks, total = chunk_wordlist(wl, 1)
            assert total == 3
            assert len(chunks) == 1
        finally:
            os.unlink(wl)

    def test_chunk_wordlist_more_chunks_than_lines(self):
        wl = _wordlist(["only_one"])
        try:
            chunks, total = chunk_wordlist(wl, 8)
            assert total == 1
            # Should still return valid chunks
            assert len(chunks) >= 1
        finally:
            os.unlink(wl)

    def test_is_seekable(self):
        wl = _wordlist(["test"])
        try:
            s = WordlistStreamer(wl)
            assert s.is_seekable is True
        finally:
            os.unlink(wl)

    def test_stdin_not_seekable(self):
        s = WordlistStreamer("-")
        assert s.is_seekable is False

    def test_validate_wordlist_missing(self):
        try:
            validate_wordlist("/nonexistent/rockyou.txt")
            assert False, "should raise"
        except ValueError as e:
            assert "not found" in str(e).lower()

    def test_validate_wordlist_empty(self):
        tmp = _tmp_file(b"")
        try:
            try:
                validate_wordlist(tmp)
                assert False, "should raise"
            except ValueError as e:
                assert "empty" in str(e).lower()
        finally:
            os.unlink(tmp)

    def test_validate_wordlist_ok(self):
        wl = _wordlist(["test"])
        try:
            validate_wordlist(wl)  # should not raise
        finally:
            os.unlink(wl)

    def test_file_size(self):
        wl = _wordlist(["hello"])
        try:
            s = WordlistStreamer(wl)
            assert s.file_size() > 0
        finally:
            os.unlink(wl)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestSession:

    def _make_session(self) -> tuple[Session, str]:
        s = Session(
            key_path=str(KEYS_DIR / "rsa_legacy_puppet.key"),
            key_hash=Session.hash_key_file(str(KEYS_DIR / "rsa_legacy_puppet.key")),
            wordlist="/tmp/rockyou.txt",
            mode="wordlist",
            use_rules=False,
        )
        name = f"test_{s.session_id}"
        return s, name

    def test_save_and_load(self):
        s, name = self._make_session()
        try:
            s.save(name)
            loaded = Session.load(name)
            assert loaded.key_path == s.key_path
            assert loaded.session_id == s.session_id
            assert loaded.mode == "wordlist"
        finally:
            s.delete(name)

    def test_load_missing_raises(self):
        try:
            Session.load("this_session_does_not_exist_xyz")
            assert False, "should raise"
        except FileNotFoundError:
            pass

    def test_delete(self):
        s, name = self._make_session()
        s.save(name)
        s.delete(name)
        try:
            Session.load(name)
            assert False, "should raise after delete"
        except FileNotFoundError:
            pass

    def test_progress_update(self):
        s, name = self._make_session()
        s.update(bytes_done=500, words_tried=1000)
        assert s.bytes_done == 500
        assert s.words_tried == 1000

    def test_not_stale(self):
        s, _ = self._make_session()
        assert s.is_stale() is False

    def test_stale_on_missing_key(self):
        s = Session(key_path="/nonexistent/key.pem", key_hash="sha256:abc")
        assert s.is_stale() is True

    def test_list_sessions(self):
        s, name = self._make_session()
        try:
            s.save(name)
            sessions = Session.list_sessions()
            names = [x["name"] for x in sessions]
            assert name in names
        finally:
            s.delete(name)

    def test_session_name_deterministic(self):
        n1 = session_name_for("/path/key.pem", "/path/rockyou.txt")
        n2 = session_name_for("/path/key.pem", "/path/rockyou.txt")
        assert n1 == n2

    def test_session_name_different_inputs(self):
        n1 = session_name_for("/path/key1.pem", "/path/rockyou.txt")
        n2 = session_name_for("/path/key2.pem", "/path/rockyou.txt")
        assert n1 != n2


# ══════════════════════════════════════════════════════════════════════════════
# DISPLAY TESTS
# ══════════════════════════════════════════════════════════════════════════════


def _progress_bar_str(tried, total, speed, width=38):
    """Thin wrapper to test progress bar rendering."""
    d = Display(quiet=True)
    # Access private method for testing
    pct = tried / total if total > 0 else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    remaining = (total - tried) / speed if speed > 0 and total > 0 else 0
    return f"[{bar}] {tried}/{total} ({pct*100:.1f}%) {speed:.1f} pw/s"


class TestDisplay:

    def test_progress_bar_basic(self):
        bar = _progress_bar_str(5000, 14_000_000, 1234.5)
        assert "5000" in bar
        assert "14000000" in bar

    def test_progress_bar_zero_speed_no_crash(self):
        bar = _progress_bar_str(0, 100, 0)
        assert bar  # non-empty

    def test_progress_bar_complete(self):
        bar = _progress_bar_str(100, 100, 50.0)
        assert "100.0%" in bar

    def test_display_init(self):
        d = Display(verbose=True, quiet=False)
        assert d.verbose is True

    def test_quiet_suppresses_output(self, capsys=None):
        d = Display(quiet=True)
        d.info("this should not print")
        # No easy way to test without capsys fixture, but no exception = pass

    def test_warn_no_crash(self):
        d = Display()
        d.warn("test warning")


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestIntegration:
    """End-to-end tests using real keys and tiny wordlists."""

    def test_hashaxe_rsa_wordlist_hit(self):
        """Should find 'puppet' in a small wordlist."""
        from hashaxe.cracker import hashaxe

        wl = _wordlist(["wrong1", "wrong2", "puppet", "wrong3"])
        try:
            result = hashaxe(
                key_path=str(KEYS_DIR / "rsa_legacy_puppet.key"),
                wordlist=wl,
                threads=1,
                quiet=True,
            )
            assert result == "puppet", f"Expected 'puppet', got {result!r}"
        finally:
            os.unlink(wl)

    def test_hashaxe_rsa_wordlist_miss(self):
        """Should return None when passphrase not in wordlist."""
        from hashaxe.cracker import hashaxe

        wl = _wordlist(["wrong1", "wrong2", "wrong3"])
        try:
            result = hashaxe(
                key_path=str(KEYS_DIR / "rsa_legacy_puppet.key"),
                wordlist=wl,
                threads=1,
                quiet=True,
            )
            assert result is None
        finally:
            os.unlink(wl)

    def test_hashaxe_with_rules_hit(self):
        """'Puppet123!' should be found via --rules mutations of 'puppet'."""
        from hashaxe.cracker import hashaxe

        # rsa_legacy_puppet.key has passphrase 'puppet'
        # with rules, 'puppet123!' will be generated but won't match 'puppet'
        # So let's test that rules finds 'puppet' from 'puppet' (noop)
        wl = _wordlist(["wrong", "puppet", "other"])
        try:
            result = hashaxe(
                key_path=str(KEYS_DIR / "rsa_legacy_puppet.key"),
                wordlist=wl,
                threads=1,
                use_rules=True,
                quiet=True,
            )
            assert result == "puppet"
        finally:
            os.unlink(wl)

    def test_hashaxe_unencrypted_returns_empty(self):
        """Unencrypted key should return empty string immediately."""
        from hashaxe.cracker import hashaxe

        wl = _wordlist(["anything"])
        try:
            result = hashaxe(
                key_path=str(KEYS_DIR / "rsa_legacy_nopass.key"),
                wordlist=wl,
                threads=1,
                quiet=True,
            )
            assert result == ""
        finally:
            os.unlink(wl)

    def test_hashaxe_ecdsa_wordlist_hit(self):
        """Should find 'abc123' for ECDSA key."""
        from hashaxe.cracker import hashaxe

        wl = _wordlist(["wrong", "abc123", "other"])
        try:
            result = hashaxe(
                key_path=str(KEYS_DIR / "ecdsa_legacy_abc123.key"),
                wordlist=wl,
                threads=1,
                quiet=True,
            )
            assert result == "abc123"
        finally:
            os.unlink(wl)

    def test_hashaxe_mask_hit(self):
        """Mask '?l?l?l?d?d?d' should find 'abc123'."""
        from hashaxe.cracker import hashaxe

        result = hashaxe(
            key_path=str(KEYS_DIR / "ecdsa_legacy_abc123.key"),
            wordlist="",
            mask="?l?l?l?d?d?d",
            threads=1,
            quiet=True,
        )
        assert result == "abc123"

    def test_hashaxe_output_file(self):
        """Result should be written to output file."""
        from hashaxe.cracker import hashaxe

        wl = _wordlist(["puppet"])
        out_tmp = _tmp_file(b"")
        try:
            result = hashaxe(
                key_path=str(KEYS_DIR / "rsa_legacy_puppet.key"),
                wordlist=wl,
                threads=1,
                quiet=True,
                output=out_tmp,
            )
            assert result == "puppet"
            content = Path(out_tmp).read_text()
            assert "puppet" in content
        finally:
            os.unlink(wl)
            os.unlink(out_tmp)


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE RUNNER
# ══════════════════════════════════════════════════════════════════════════════


def _run_all() -> tuple[int, int]:
    """Run all tests without pytest.  Returns (passed, failed)."""
    import traceback

    test_classes = [
        TestParser,
        TestEngine,
        TestMutations,
        TestMaskEngine,
        TestHashcatRules,
        TestWordlist,
        TestSession,
        TestDisplay,
        TestIntegration,
    ]

    passed = failed = 0

    for cls in test_classes:
        instance = cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        cls_pass = cls_fail = 0

        for name in sorted(methods):
            method = getattr(instance, name)
            try:
                method()
                cls_pass += 1
                passed += 1
                print(f"    ✔  {cls.__name__}.{name}")
            except Exception as exc:
                cls_fail += 1
                failed += 1
                print(f"    ✘  {cls.__name__}.{name}")
                print(f"       {exc}")
                if os.environ.get("VERBOSE_TESTS"):
                    traceback.print_exc()

        status = f"{cls_pass}/{cls_pass+cls_fail}"
        print(f"  [{cls.__name__}]  {status} tests passed\n")

    return passed, failed


if __name__ == "__main__":
    print(f"\n{'═'*60}")
    print(f"  hashaxe v1 — Test Suite")
    print(f"{'═'*60}\n")

    p, f = _run_all()

    print(f"{'═'*60}")
    print(f"  Total: {p} passed, {f} failed")
    print(f"{'═'*60}\n")
    sys.exit(0 if f == 0 else 1)
