# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣 FILE: hashaxe/formats/base.py
#  Abstract base classes for the format plugin system.
#  Defines FormatTarget, FormatMatch, and BaseFormat contract for all handlers.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️  WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal and unethical.
# ==========================================================================================
# ⚠️  Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
hashaxe.formats.base — Abstract base classes for the format plugin system.

Defines the contract every format handler must implement:

  • FormatDifficulty — computational cost classification for ETA and strategy selection
  • FormatTarget     — picklable dataclass holding extracted crypto material for workers
  • FormatMatch      — identification result with confidence score from ``can_handle()``
  • BaseFormat       — abstract handler with identify / parse / verify contract

Architecture overview::

    File/Hash Input
         │
         ▼
    FormatRegistry.identify(data, path)
         │  iterates all registered BaseFormat subclasses
         │  returns highest-confidence FormatMatch
         ▼
    BaseFormat.parse(data, path) ──► FormatTarget (pickled → worker pool)
                                          │
                              ┌──────────┘
                              ▼  (inner loop — millions/sec)
                    BaseFormat.verify(target, password)
                              │
                    ┌─── False → next candidate
                    └─── True  → verify_full(target, password)
                                      │
                              ┌─── False → false positive, continue
                              └─── True  → PASSWORD FOUND 🎯

Design decisions
----------------
``FormatTarget`` is a plain dataclass (not ABC) so it pickles cleanly across
multiprocessing boundaries without ``__reduce__`` hacks.  All values in
``format_data`` must be JSON-serialisable primitives or ``bytes``.

``verify()`` is the hot path (called millions of times per second).
Implementations MUST be allocation-free and branch-minimal.  No logging,
no I/O, no library calls with hidden allocations.

``verify_full()`` is called exactly once after ``verify()`` returns ``True``.
It may be expensive: full library parse, MAC verification, signature check.
It MUST never produce false positives — this is the final gate.

``difficulty()`` drives dispatcher strategy:
  - TRIVIAL/FAST  → GPU batch mode via OpenCL/CUDA kernels
  - MEDIUM        → hybrid CPU+GPU with adaptive batch sizing
  - SLOW/EXTREME  → CPU-only, argon2-cffi / hashlib native, single-digit/sec
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

__all__ = [
    "CHUNK_SIZES",
    "BaseFormat",
    "FormatDifficulty",
    "FormatMatch",
    "FormatTarget",
]

logger = logging.getLogger(__name__)


# ── Difficulty classification ──────────────────────────────────────────────────


class FormatDifficulty(Enum):
    """
    Computational cost classification for each password test.

    Used by the dispatcher to choose GPU vs CPU strategy and estimate ETA.

    Approximate throughput on RTX 4090 / Ryzen 9 7950X (2026 baseline):

    +-----------+----------------------------------+---------------------+
    | Level     | Representative formats           | Throughput          |
    +===========+==================================+=====================+
    | TRIVIAL   | MD5, SHA-1, NTLM, LM             | >5 billion/sec GPU  |
    +-----------+----------------------------------+---------------------+
    | FAST      | SHA-256crypt ($5$), MySQL 4.1    | ~500 million/sec    |
    +-----------+----------------------------------+---------------------+
    | MEDIUM    | bcrypt $2b$10, PBKDF2-HMAC-4096  | ~200k/sec GPU       |
    +-----------+----------------------------------+---------------------+
    | SLOW      | bcrypt $2b$12, WPA2-PMKID        | ~5k/sec GPU         |
    +-----------+----------------------------------+---------------------+
    | EXTREME   | Argon2id (t=3,m=65536), scrypt   | ~10/sec CPU-only    |
    +-----------+----------------------------------+---------------------+
    """

    TRIVIAL = auto()
    FAST = auto()
    MEDIUM = auto()
    SLOW = auto()
    EXTREME = auto()


# ── Dynamic Chunking Mapping ───────────────────────────────────────────────────

CHUNK_SIZES: dict[FormatDifficulty, int] = {
    FormatDifficulty.EXTREME: 1,  # argon2id, scrypt
    FormatDifficulty.SLOW: 1,  # bcrypt $12/$14, WPA2
    FormatDifficulty.MEDIUM: 100,  # bcrypt $10, PBKDF2
    FormatDifficulty.FAST: 5_000,  # SHA-256crypt, MD5crypt
    FormatDifficulty.TRIVIAL: 50_000,  # MD5, NTLM, SHA-1
}


# ── Format target (picklable crypto context) ───────────────────────────────────


@dataclass
class FormatTarget:
    """
    Universal picklable container for extracted crypto material.

    Each format handler populates ``format_id`` and ``format_data`` with
    whatever the hot-path ``verify()`` method needs at hashaxe time.  Workers
    receive a copy via pickle — keep it lightweight.

    **Pickle contract**: ``format_data`` must contain only:
      - ``bool``, ``int``, ``float``, ``str``
      - ``bytes`` (pickle handles natively)
      - ``list`` / ``dict`` of the above (no nested custom objects)

    Attributes:
        format_id:    Dotted identifier for the owning handler.
                      Convention: ``"<category>.<variant>"``
                      Examples: ``"ssh.openssh"``, ``"hash.md5"``,
                      ``"archive.zip"``, ``"office.docx"``.
        display_name: Human-readable label shown in the hashaxe banner.
                      Example: ``"OpenSSH RSA-4096 (aes256-cbc)"``.
        source_path:  Original filesystem path as a string, for logging
                      and result display.  Empty string if input was stdin.
        is_encrypted: ``True`` if the target actually requires cracking.
                      ``False`` means it was found unprotected — log and skip.
        difficulty:   Computational difficulty used by dispatcher for
                      strategy selection and ETA estimation.
        format_data:  Format-specific crypto material extracted by ``parse()``.
                      The exact keys are defined by each ``BaseFormat`` subclass
                      and documented in that subclass's ``parse()`` docstring.
        _legacy_pk:   Internal compatibility shim for wrapping pre-refactor
                      ``ParsedKey`` objects.  New handlers must not use this.
                      Will be removed in v2.0.
    """

    format_id: str = ""
    display_name: str = ""
    source_path: str = ""
    is_encrypted: bool = True
    difficulty: FormatDifficulty = FormatDifficulty.MEDIUM
    format_data: dict[str, Any] = field(default_factory=dict)

    # Internal compatibility shim — not part of the public API.
    # Stores legacy ParsedKey objects so existing GPU/SIMD dispatch paths
    # continue to function during the incremental plugin migration.
    # Will be removed in v2.0 once all handlers are fully migrated.
    _legacy_pk: Any = field(default=None, repr=False, compare=False)


# ── Format match (identification result) ──────────────────────────────────────


@dataclass
class FormatMatch:
    """
    Result returned by :meth:`BaseFormat.can_handle`.

    The ``FormatRegistry`` collects all non-``None`` matches and selects the
    handler with the highest ``confidence`` score to proceed with ``parse()``.

    Confidence conventions:

    +-------+------------------------------------------------------+
    | Score | Meaning                                              |
    +=======+======================================================+
    | 1.0   | Definitive — unique magic bytes or file signature    |
    +-------+------------------------------------------------------+
    | 0.9   | Very high — strong structural match                  |
    +-------+------------------------------------------------------+
    | 0.7   | High — multiple heuristics agree                     |
    +-------+------------------------------------------------------+
    | 0.5   | Medium — extension + partial structure match         |
    +-------+------------------------------------------------------+
    | 0.3   | Low — extension only, no structural validation       |
    +-------+------------------------------------------------------+

    Attributes:
        format_id:  The handler that produced this match.
        confidence: Normalised score in ``[0.0, 1.0]``.  Values outside
                    this range will be clamped by the registry.
        handler:    Reference to the ``BaseFormat`` instance that matched.
                    Excluded from ``repr`` to avoid circular output.
        metadata:   Optional key-value pairs for disambiguation or display.
                    Example: ``{"variant": "ppk-v3", "cipher": "aes256-cbc"}``.
    """

    format_id: str = ""
    confidence: float = 0.0
    handler: BaseFormat | None = field(default=None, repr=False)
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Clamp confidence to valid range — guard against handler bugs.
        self.confidence = max(0.0, min(1.0, self.confidence))


# ── Base format handler ABC ────────────────────────────────────────────────────


class BaseFormat(ABC):
    """
    Abstract base class for all format handlers.

    Every concrete handler must:
      1. Set unique ``format_id`` and ``format_name`` class variables.
      2. Implement all four abstract methods.
      3. Register itself with ``FormatRegistry`` (via the ``@register_format``
         decorator or explicit ``registry.add()`` call).

    **Thread safety**: Handler instances are shared across threads.
    ``verify()`` and ``verify_full()`` must be stateless and re-entrant.
    Any mutable state must live in ``FormatTarget.format_data``, not on
    the handler itself.

    **Subclassing example**::

        @register_format
        class NTLM(BaseFormat):
            format_id   = "hash.ntlm"
            format_name = "NTLM"

            def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
                stripped = data.strip()
                if len(stripped) == 32 and all(c in b"0123456789abcdefABCDEF" for c in stripped):
                    return FormatMatch(format_id=self.format_id, confidence=0.7, handler=self)
                return None

            def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
                return FormatTarget(
                    format_id    = self.format_id,
                    display_name = "NTLM Hash",
                    source_path  = str(path or ""),
                    difficulty   = self.difficulty(),
                    format_data  = {"hash_hex": data.strip().lower().decode()},
                )

            def verify(self, target: FormatTarget, password: bytes) -> bool:
                import hashlib
                return hashlib.new("md4", password).hexdigest() == target.format_data["hash_hex"]

            def verify_full(self, target: FormatTarget, password: bytes) -> bool:
                return self.verify(target, password)   # NTLM has no outer wrapper

            def difficulty(self) -> FormatDifficulty:
                return FormatDifficulty.TRIVIAL
    """

    # ── Class-level identity (must be overridden) ─────────────────────────
    format_id: str = ""  # e.g. "ssh.openssh", "hash.md5", "archive.zip"
    format_name: str = ""  # e.g. "OpenSSH Private Key", "MD5 Raw Hash"

    # ── Identification ─────────────────────────────────────────────────────

    @abstractmethod
    def can_handle(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> FormatMatch | None:
        """
        Determine whether this handler can process the given input.

        Implementations should prefer structural / magic-byte checks over
        file-extension heuristics alone.  Extension-only matches should
        return ``confidence ≤ 0.4`` so a structural match from another
        handler can win.

        This method is called on every registered handler for each input.
        Keep it fast: no I/O, no expensive parsing.  Scan the first few
        hundred bytes at most.

        Args:
            data: Raw bytes of the input (full file contents or hash string).
                  Callers guarantee ``len(data) > 0``.
            path: Optional filesystem path.  Use for extension hints only —
                  the file may have been renamed or piped from stdin.

        Returns:
            A :class:`FormatMatch` with ``confidence > 0`` if this handler
            recognises the input, or ``None`` if it does not.
        """
        ...

    # ── Parsing ────────────────────────────────────────────────────────────

    @abstractmethod
    def parse(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> FormatTarget:
        """
        Extract all crypto material needed for cracking.

        Called once at startup on the main process.  The returned
        :class:`FormatTarget` is pickled and broadcast to every worker in
        the pool — keep ``format_data`` lean (no redundant copies of raw bytes).

        Implementations should:
          - Fully validate structure and raise :class:`ValueError` on corruption.
          - Set ``is_encrypted = False`` if the target needs no cracking.
          - Document the exact keys populated in ``format_data`` in the
            subclass docstring.

        Args:
            data: Raw bytes of the input.
            path: Optional filesystem path.

        Returns:
            A fully populated :class:`FormatTarget`.

        Raises:
            ValueError: If ``data`` is structurally invalid or unsupported.
            NotImplementedError: If a detected sub-variant is not yet handled.
        """
        ...

    # ── Verification — hot path ────────────────────────────────────────────

    @abstractmethod
    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """
        Fast-path password check called in the inner cracking loop.

        **Performance contract** (non-negotiable):
          - Zero heap allocations where possible (reuse pre-allocated buffers).
          - No logging, no I/O, no system calls outside the crypto primitive.
          - No exception handling — let errors propagate to the worker harness.
          - Must be stateless and re-entrant (called concurrently from threads).

        **Correctness contract**:
          - False positives are acceptable — :meth:`verify_full` will confirm.
          - False negatives are **never** acceptable — must not return ``False``
            for the correct password.  When in doubt, return ``True`` and let
            ``verify_full`` reject.

        Args:
            target:   The :class:`FormatTarget` produced by :meth:`parse`.
            password: Candidate password as raw bytes (encoding is caller's
                      responsibility — typically UTF-8 with Latin-1 fallback).

        Returns:
            ``True`` if ``password`` is a plausible match; ``False`` otherwise.
        """
        ...

    @abstractmethod
    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        """
        Definitive password confirmation — called once after :meth:`verify` returns ``True``.

        This is the final gate before declaring success.  It may be expensive:
        full library parse, HMAC-MAC verification, signature validation, etc.

        **Correctness contract** (absolute):
          - MUST return ``False`` for any incorrect password.
          - Zero false positives are the invariant that makes the overall
            system correct.  A false positive here terminates the hashaxe and
            reports a wrong password to the user.

        Args:
            target:   The :class:`FormatTarget` produced by :meth:`parse`.
            password: The candidate that passed :meth:`verify`.

        Returns:
            ``True`` if and only if ``password`` is definitively correct.
        """
        ...

    # ── Metadata ───────────────────────────────────────────────────────────

    def difficulty(self) -> FormatDifficulty:
        """
        Return the computational difficulty of this format.

        Override in subclasses that know their cost at class definition time.
        For formats where cost depends on parsed parameters (e.g. bcrypt cost
        factor, PBKDF2 iteration count), override this to inspect
        ``target.format_data`` — but note this method does not receive
        ``target``.  In those cases, store the difficulty in
        ``FormatTarget.difficulty`` during :meth:`parse` instead.

        Default: :attr:`FormatDifficulty.MEDIUM`.
        """
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        """
        Return key-value pairs rendered in the hashaxe banner.

        Keys and values must be short strings suitable for single-line display.
        Override to expose format-specific parameters (cipher, KDF rounds, etc.).

        Example return value::

            {
                "Type":    "ppk-v3-rsa",
                "Cipher":  "aes256-cbc",
                "MAC":     "hmac-sha256",
                "Argon2t": "16",
            }

        Args:
            target: The parsed :class:`FormatTarget` for this input.

        Returns:
            Ordered dict of label → value pairs.  Default returns format name only.
        """
        return {"Format": self.format_name}

    # ── Dunder helpers ─────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} format_id={self.format_id!r}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseFormat):
            return NotImplemented
        return self.format_id == other.format_id

    def __hash__(self) -> int:
        return hash(self.format_id)
