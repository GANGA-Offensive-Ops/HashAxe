# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/wordlist.py
#  Memory-safe wordlist handling with streaming and chunking for distributed workers.
#  Zero duplication design using byte-offset ranges instead of line copies.
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
wordlist.py — Memory-safe wordlist handling.

Fixes the OOM bug in v1.0: the original _chunk_wordlist() loaded the entire
wordlist into RAM as a list-of-lists.  For rockyou.txt (133 MB) × 16 workers
that's 2+ GB just for wordlist copies.

This module provides:
  • WordlistStreamer  — streams lines from disk, never loads all into RAM
  • chunk_wordlist()  — produces byte-offset ranges (not line copies) for workers
  • WordlistSource    — abstraction over file / stdin / generator

Each worker receives a (start_byte, end_byte) range and seeks directly to
its chunk in the file.  Zero duplication, constant memory usage.

Also supports:
  • --stdin  (wordlist piped via stdin)
  • Compressed wordlists (.gz, .bz2, .xz)
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import sys
import tempfile
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import Optional

from hashaxe.formats.base import CHUNK_SIZES, FormatDifficulty

# ── Rust native acceleration (9.7x faster count_lines via mmap+memchr) ────────
try:
    import hashaxe_wordlist_rs

    _HAS_NATIVE = True
except ImportError:
    _HAS_NATIVE = False


class WordlistStreamer:
    """
    Stream passphrase candidates from a wordlist file.

    Supports plain text, .gz, .bz2, .xz, and stdin ('-').
    Handles both bytes and str lines transparently.
    """

    def __init__(self, path: str, encoding: str = "utf-8"):
        self.path = path
        self.encoding = encoding
        self._is_stdin = path == "-"
        self._is_compressed = path.endswith((".gz", ".bz2", ".xz"))

    @property
    def is_seekable(self) -> bool:
        """True if we can split the wordlist into byte-range chunks."""
        return not self._is_stdin and not self._is_compressed

    def count_lines(self) -> int:
        """Count total lines (for progress calculation).

        Uses Rust mmap+memchr (9.7x faster) if hashaxe_native is installed,
        falls back to Python C-level buf.count(b'\\n') otherwise.
        """
        if self._is_stdin:
            return 0  # unknown

        # Fast path: Rust mmap + SIMD memchr
        if _HAS_NATIVE:
            try:
                if self._is_compressed:
                    return hashaxe_wordlist_rs.count_lines_compressed(self.path)
                return hashaxe_wordlist_rs.count_lines(self.path)
            except Exception:
                pass  # fall through to Python path

        # Python fallback
        count = 0
        with self._open_raw() as f:
            while True:
                buf = f.read(1024 * 1024 * 8)  # 8MB chunks
                if not buf:
                    break
                count += buf.count(b"\n")
        return count

    def file_size(self) -> int:
        """Return file size in bytes (for byte-range chunking)."""
        if not self.is_seekable:
            return 0
        return os.path.getsize(self.path)

    def lines(self, start_byte: int = 0, end_byte: int = -1) -> Generator[bytes, None, None]:
        """
        Yield raw bytes lines from start_byte to end_byte.
        If end_byte == -1, read to EOF.
        Skips partial first line when start_byte > 0.
        """
        if self._is_stdin:
            for line in sys.stdin.buffer:
                yield line
            return

        with self._open_raw() as f:
            if start_byte > 0:
                f.seek(start_byte)
                f.readline()  # skip partial line at boundary

            pos = f.tell() if hasattr(f, "tell") else 0
            for raw_line in f:
                yield raw_line
                if end_byte > 0:
                    pos += len(raw_line)
                    if pos >= end_byte:
                        # Yield the remaining buffered content if we hit the end byte exactly on a non-newline ending word
                        break

    def _open_raw(self):
        """Open the wordlist with appropriate decompression."""
        if self.path.endswith(".gz"):
            return gzip.open(self.path, "rb")
        if self.path.endswith(".bz2"):
            return bz2.open(self.path, "rb")
        if self.path.endswith(".xz"):
            return lzma.open(self.path, "rb")
        return open(self.path, "rb")


def chunk_wordlist(
    path: str,
    n_chunks: int = 0,
    chunk_size_bytes: int = 0,
    difficulty: FormatDifficulty = FormatDifficulty.MEDIUM,
    rules: bool = False,
) -> tuple[list[tuple[int, int]], int]:
    streamer = WordlistStreamer(path)

    if not streamer.is_seekable:
        return [(0, -1)], 0

    file_size = streamer.file_size()
    if chunk_size_bytes > 0 and chunk_size_bytes <= 10:
        # EXTREME/SLOW/MEDIUM hash — estimate lines instead of counting
        total_lines = max(1, file_size // 10) if file_size > 0 else 0
    else:
        total_lines = streamer.count_lines()

    if file_size == 0 or (n_chunks <= 1 and chunk_size_bytes <= 0):
        return [(0, -1)], total_lines

    if chunk_size_bytes > 0:
        chunk_size = chunk_size_bytes
        n_chunks = max(1, (file_size // chunk_size) + (1 if file_size % chunk_size > 0 else 0))
    else:
        words_per_chunk = CHUNK_SIZES.get(difficulty, 1000)

        # If rules are enabled, each word produces ~470 candidates.
        # We must divide the chunk size to keep the memory footprint constant,
        # otherwise a FAST chunk (5000 words * 470 = 2.3M candidates) kills performance.
        if rules:
            words_per_chunk = max(1, words_per_chunk // 300)

        chunk_size = file_size // max(1, n_chunks)

    chunks: list[tuple[int, int]] = []

    for i in range(n_chunks):
        start = i * chunk_size
        end = min((i + 1) * chunk_size if i < n_chunks - 1 else file_size, file_size)
        chunks.append((start, end))

    return chunks, total_lines


def validate_wordlist(path: str) -> None:
    """
    Raise ValueError with a helpful message if the wordlist is unusable.
    """
    if path == "-":
        return  # stdin is always valid

    p = Path(path)
    if not p.exists():
        raise ValueError(
            f"Wordlist not found: {path}\n"
            f"  Common locations:\n"
            f"  • ./test_files/password.txt\n"
            f"  • /usr/share/seclists/Passwords/rockyou.txt\n"
            f"  • ~/wordlists/rockyou.txt"
        )
    if not p.is_file():
        raise ValueError(f"Wordlist path is not a file: {path}")
    if p.stat().st_size == 0:
        raise ValueError(f"Wordlist is empty: {path}")
