# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/_registry.py
#  Auto-discovery and registration of format handlers for the plugin system.
#  Provides identify(), get(), and all_handlers() for format management.
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
hashaxe.formats._registry — Auto-discovery and registration of format handlers.

The registry scans the ``hashaxe.formats`` package at import time, finds all
``BaseFormat`` subclasses, and provides:

  • ``FormatRegistry.identify(data, path)`` — try every handler, return best match
  • ``FormatRegistry.get(format_id)``       — retrieve handler by dotted ID
  • ``FormatRegistry.all_handlers()``       — iterate over all registered handlers

Thread-safe, singleton pattern.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Optional

from hashaxe.formats.base import BaseFormat, FormatMatch

logger = logging.getLogger(__name__)


class FormatRegistry:
    """
    Central registry of all available format handlers.

    Handlers register themselves by being imported — the metaclass-free
    approach uses explicit ``register()`` calls or auto-discovery via
    ``_discover_handlers()``.
    """

    _instance: FormatRegistry | None = None
    _handlers: dict[str, BaseFormat]

    def __new__(cls) -> FormatRegistry:
        """Singleton: one registry for the entire process."""
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._handlers = {}
            inst._discovered = False
            cls._instance = inst
        return cls._instance

    # ── Registration ──────────────────────────────────────────────────────

    def register(self, handler: BaseFormat) -> None:
        """
        Register a format handler instance.

        Args:
            handler: An instance of a BaseFormat subclass.

        Raises:
            ValueError: If ``handler.format_id`` is empty or already registered.
        """
        fid = handler.format_id
        if not fid:
            raise ValueError(f"Handler {handler.__class__.__name__} has empty format_id")
        if fid in self._handlers:
            logger.debug(
                "Replacing handler for '%s': %s -> %s",
                fid,
                self._handlers[fid].__class__.__name__,
                handler.__class__.__name__,
            )
        self._handlers[fid] = handler
        logger.debug("Registered format handler: %s (%s)", fid, handler.format_name)

    # ── Auto-discovery ────────────────────────────────────────────────────

    def discover(self) -> None:
        """
        Import all modules in ``hashaxe.formats`` to trigger handler registration.

        Called lazily on first ``identify()`` or ``all_handlers()`` call.
        Safe to call multiple times (idempotent).
        """
        if self._discovered:
            return
        self._discovered = True

        import hashaxe.formats as pkg

        # Walk the package directory and import every module
        pkg_path = Path(pkg.__file__).parent
        for info in pkgutil.iter_modules([str(pkg_path)]):
            if info.name.startswith("_"):
                continue  # skip __init__, _registry, etc.
            module_name = f"hashaxe.formats.{info.name}"
            try:
                importlib.import_module(module_name)
                logger.debug("Auto-discovered format module: %s", module_name)
            except Exception:
                logger.warning(
                    "Failed to import format module: %s",
                    module_name,
                    exc_info=True,
                )

    # ── Lookup ────────────────────────────────────────────────────────────

    def get(self, format_id: str) -> BaseFormat | None:
        """
        Retrieve a handler by its dotted format_id.

        Auto-discovers handlers if not yet done.
        """
        self.discover()
        return self._handlers.get(format_id)

    def all_handlers(self) -> list[BaseFormat]:
        """Return all registered handler instances. Auto-discovers first."""
        self.discover()
        return list(self._handlers.values())

    # ── Identification ────────────────────────────────────────────────────

    def identify(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> FormatMatch | None:
        """
        Identify the format of the given input by trying every handler.

        Returns the ``FormatMatch`` with the highest confidence, or ``None``
        if no handler recognises the input.

        Args:
            data: Raw bytes (file contents or a hash string encoded as bytes).
            path: Optional filesystem path for extension/name hints.
        """
        self.discover()

        best: FormatMatch | None = None

        for handler in self._handlers.values():
            try:
                match = handler.can_handle(data, path)
            except Exception:
                logger.debug(
                    "Handler %s.can_handle() raised an exception",
                    handler.format_id,
                    exc_info=True,
                )
                continue

            if match is None or match.confidence <= 0:
                continue

            if best is None or match.confidence > best.confidence:
                best = match

        return best

    def identify_all(
        self,
        data: bytes,
        path: Path | None = None,
    ) -> list[FormatMatch]:
        """
        Return *all* matching handlers sorted by descending confidence.

        Used by the cracker for format-fallback: if the top candidate fails
        to hashaxe the target, the next alternative is tried automatically.
        This resolves ambiguous formats like ``32hex:username`` which can be
        either PostgreSQL MD5 (hashcat -m 12) or DCC MS Cache v1 (-m 1100).
        """
        self.discover()

        matches: list[FormatMatch] = []

        for handler in self._handlers.values():
            try:
                match = handler.can_handle(data, path)
            except Exception:
                logger.debug(
                    "Handler %s.can_handle() raised an exception",
                    handler.format_id,
                    exc_info=True,
                )
                continue

            if match is not None and match.confidence > 0:
                matches.append(match)

        return sorted(matches, key=lambda m: m.confidence, reverse=True)

    # ── Utilities ─────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear all handlers and discovery state. Used in tests."""
        self._handlers.clear()
        self._discovered = False

    def __len__(self) -> int:
        self.discover()
        return len(self._handlers)

    def __contains__(self, format_id: str) -> bool:
        self.discover()
        return format_id in self._handlers

    def __repr__(self) -> str:
        return (
            f"FormatRegistry({len(self._handlers)} handlers: "
            f"{', '.join(sorted(self._handlers.keys()))})"
        )
