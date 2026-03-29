# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/__init__.py
#  Universal format handler plugin system with auto-discovery registry.
#  Supports SSH keys, archives, documents, hashes, databases, tokens, and more.
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
hashaxe.formats — Universal format handler plugin system.

Architecture:
  Every hashaxeable format (SSH keys, ZIP files, hashes, PDFs, etc.) is
  represented by a subclass of ``BaseFormat``.  Each format handler provides:

    • ``can_handle(data, path)``  — identify whether this handler matches a given input
    • ``parse(data, path)``       — extract a picklable ``FormatTarget`` from raw input
    • ``verify(target, password)``     — fast-path password check (hot loop, millions/sec)
    • ``verify_full(target, password)``— full confirmation (called once after fast-path hit)

  ``FormatRegistry`` auto-discovers all installed format handlers at import time.
  New formats are added by subclassing ``BaseFormat`` inside ``hashaxe/formats/``.

Developed by Bhanu Guragain · GANGA Offensive Ops
"""

from __future__ import annotations

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

# Import all format handlers to trigger auto-registration
from hashaxe.formats import encoded_base64  # noqa: F401

__all__ = [
    "BaseFormat",
    "FormatDifficulty",
    "FormatMatch",
    "FormatRegistry",
    "FormatTarget",
]
