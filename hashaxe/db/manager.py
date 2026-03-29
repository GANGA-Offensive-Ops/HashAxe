# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/db/manager.py
#  CrackDB — SQLite-backed results database manager for logging successful cracks.
#  Stores metadata: source, format, passphrase, attack mode, performance, hardware info.
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
CrackDB — SQLite-backed results database manager.

Every successful hashaxe is logged with full metadata: source, format,
passphrase, attack mode, performance metrics, and hardware info.

Storage location: ~/.shadowhashaxe/results.db  (auto-created)
Also appends to:  ~/.shadowhashaxe/passwords.txt  (potfile)

Thread-safe: Each call creates its own connection.
"""
from __future__ import annotations

import hashlib
import logging
import os
import platform
import sqlite3
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from hashaxe.db.export import export_csv, export_json, export_to_file
from hashaxe.db.schema import DB_VERSION, SCHEMA_SQL

log = logging.getLogger(__name__)


# ── Default storage directory ─────────────────────────────────────────────────


def _default_db_dir() -> Path:
    """Return ~/.shadowhashaxe/ — created lazily on first write."""
    d = Path.home() / ".shadowhashaxe"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cpu_model() -> str:
    """Best-effort CPU model string."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except (FileNotFoundError, OSError):
        pass
    return platform.processor() or platform.machine()


class CrackDB:
    """SQLite-backed hashaxe results database.

    Usage::

        db = CrackDB()
        db.log_hashaxe(
            format_id="hash.md5",
            passphrase="password",
            source_path="hashes.txt",
            candidates=50000,
            elapsed_sec=0.3,
        )

        results = db.query(format_id="hash.md5")
        stats   = db.stats()
    """

    def __init__(self, db_path: str | Path | None = None):
        """Initialize with custom or default database path."""
        if db_path is None:
            self._db_path = _default_db_dir() / "results.db"
        else:
            self._db_path = Path(db_path)
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._potfile = self._db_path.parent / "passwords.txt"
        self._init_db()

    # ── Internals ─────────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        """Create a new connection with row_factory = dict."""
        # 30s timeout handles heavy concurrency without 'database is locked' errors
        conn = sqlite3.connect(str(self._db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")  # Safe and fast for WAL
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they don't exist."""
        conn = self._connect()
        try:
            conn.executescript(SCHEMA_SQL)
            # Store schema version
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                ("schema_version", str(DB_VERSION)),
            )
            conn.commit()
        finally:
            conn.close()

    # ── Logging ───────────────────────────────────────────────────────────────

    def log_hashaxe(
        self,
        format_id: str,
        passphrase: str,
        source_path: str | None = None,
        format_name: str | None = None,
        hash_preview: str | None = None,
        attack_mode: str = "wordlist",
        wordlist_path: str | None = None,
        rule_file: str | None = None,
        mask_pattern: str | None = None,
        candidates: int = 0,
        elapsed_sec: float = 0.0,
        speed_pw_s: float = 0.0,
        workers: int = 1,
        gpu_model: str | None = None,
        notes: str | None = None,
    ) -> int:
        """Log a successful hashaxe to the database.

        Args:
            format_id: Format handler ID (e.g. 'hash.md5').
            passphrase: The cracked password.
            source_path: Original file/hash source.
            format_name: Human-readable format name.
            hash_preview: First 32 chars of hash/target.
            attack_mode: Attack mode used.
            wordlist_path: Wordlist file path.
            rule_file: Rule file path.
            mask_pattern: Mask pattern used.
            candidates: Total passwords attempted.
            elapsed_sec: Time to hashaxe.
            speed_pw_s: Average speed.
            workers: Number of worker processes.
            gpu_model: GPU model if used.
            notes: Optional notes.

        Returns:
            The row ID of the inserted record.
        """
        from hashaxe import __version__

        # Compute source hash for dedup
        source_hash = None
        if source_path:
            try:
                source_hash = hashlib.sha256(Path(source_path).read_bytes()).hexdigest()[:16]
            except (OSError, FileNotFoundError):
                source_hash = hashlib.sha256(source_path.encode()).hexdigest()[:16]

        # Pre-compute passphrase hex for binary-safe storage
        passphrase_hex = passphrase.encode("utf-8").hex()

        conn = self._connect()
        try:
            cursor = conn.execute(
                """
                INSERT INTO cracks (
                    source_path, source_hash, format_id, format_name,
                    hash_preview, passphrase, passphrase_hex,
                    attack_mode, wordlist_path, rule_file, mask_pattern,
                    candidates, elapsed_sec, speed_pw_s,
                    tool_version, cpu_model, gpu_model, workers, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_path,
                    source_hash,
                    format_id,
                    format_name,
                    hash_preview,
                    passphrase,
                    passphrase_hex,
                    attack_mode,
                    wordlist_path,
                    rule_file,
                    mask_pattern,
                    candidates,
                    elapsed_sec,
                    speed_pw_s,
                    __version__,
                    _cpu_model(),
                    gpu_model,
                    workers,
                    notes,
                ),
            )
            conn.commit()
            row_id = cursor.lastrowid

            # Also append to potfile
            self._append_potfile(format_id, source_path or "inline", passphrase)

            log.info(
                "Logged hashaxe #%d: %s → %s (%.1fs, %d candidates)",
                row_id,
                format_id,
                passphrase[:20],
                elapsed_sec,
                candidates,
            )
            return row_id or 0

        finally:
            conn.close()

    def _append_potfile(self, format_id: str, source: str, passphrase: str) -> None:
        """Append to the plaintext potfile (~/.shadowhashaxe/passwords.txt)."""
        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self._potfile, "a", encoding="utf-8") as f:
                f.write(f"{ts}|{format_id}|{source}|{passphrase}\n")
        except OSError as exc:
            log.warning("Failed to append to potfile: %s", exc)

    # ── Querying ──────────────────────────────────────────────────────────────

    def query(
        self,
        format_id: str | None = None,
        source_path: str | None = None,
        passphrase: str | None = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "timestamp DESC",
    ) -> list[dict[str, Any]]:
        """Query hashaxe results with optional filters.

        Args:
            format_id: Filter by format ID (exact match).
            source_path: Filter by source path (LIKE match).
            passphrase: Filter by passphrase (exact match).
            limit: Max rows to return.
            offset: Offset for pagination.
            order_by: SQL ORDER BY clause.

        Returns:
            List of dicts, each representing a hashaxe result.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if format_id:
            conditions.append("format_id = ?")
            params.append(format_id)
        if source_path:
            conditions.append("source_path LIKE ?")
            params.append(f"%{source_path}%")
        if passphrase:
            conditions.append("passphrase = ?")
            params.append(passphrase)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        sql = f"""
            SELECT * FROM cracks
            {where}
            ORDER BY {order_by}
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        conn = self._connect()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_by_id(self, hashaxe_id: int) -> dict[str, Any] | None:
        """Get a single hashaxe result by ID."""
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM cracks WHERE id = ?", (hashaxe_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def count(self, format_id: str | None = None) -> int:
        """Count total hashaxe results, optionally filtered by format."""
        conn = self._connect()
        try:
            if format_id:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM cracks WHERE format_id = ?",
                    (format_id,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) as cnt FROM cracks").fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()

    # ── Statistics ────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Aggregate statistics across all cracked results.

        Returns dict with:
          total_cracks, formats, fastest_hashaxe, slowest_hashaxe,
          avg_speed, total_candidates, unique_passwords,
          by_format (breakdown per format_id).
        """
        conn = self._connect()
        try:
            total = conn.execute("SELECT COUNT(*) as cnt FROM cracks").fetchone()["cnt"]

            if total == 0:
                return {
                    "total_cracks": 0,
                    "formats": [],
                    "fastest_hashaxe_sec": None,
                    "slowest_hashaxe_sec": None,
                    "avg_speed_pw_s": 0.0,
                    "total_candidates": 0,
                    "unique_passwords": 0,
                    "by_format": {},
                }

            agg = conn.execute(
                """
                SELECT
                    MIN(elapsed_sec) as fastest,
                    MAX(elapsed_sec) as slowest,
                    AVG(speed_pw_s)  as avg_speed,
                    SUM(candidates)  as total_candidates,
                    COUNT(DISTINCT passphrase) as unique_pw
                FROM cracks
            """
            ).fetchone()

            formats = conn.execute(
                "SELECT DISTINCT format_id FROM cracks ORDER BY format_id"
            ).fetchall()
            format_list = [row["format_id"] for row in formats]

            # Per-format breakdown
            by_format: dict[str, dict[str, Any]] = {}
            for fmt in format_list:
                row = conn.execute(
                    """
                    SELECT
                        COUNT(*) as count,
                        AVG(speed_pw_s) as avg_speed,
                        MIN(elapsed_sec) as fastest,
                        SUM(candidates) as total_candidates
                    FROM cracks WHERE format_id = ?
                """,
                    (fmt,),
                ).fetchone()
                by_format[fmt] = dict(row) if row else {}

            return {
                "total_cracks": total,
                "formats": format_list,
                "fastest_hashaxe_sec": agg["fastest"],
                "slowest_hashaxe_sec": agg["slowest"],
                "avg_speed_pw_s": round(agg["avg_speed"] or 0, 1),
                "total_candidates": agg["total_candidates"] or 0,
                "unique_passwords": agg["unique_pw"] or 0,
                "by_format": by_format,
            }
        finally:
            conn.close()

    # ── Export ─────────────────────────────────────────────────────────────────

    def export(
        self,
        fmt: str = "json",
        path: str | None = None,
        format_id: str | None = None,
        limit: int = 10000,
    ) -> str:
        """Export results to CSV or JSON.

        Args:
            fmt: 'json' or 'csv'.
            path: If provided, write to file and return filename.
                  If None, return the formatted string.
            format_id: Optional filter by format.
            limit: Max rows.

        Returns:
            Formatted string, or filename if path was provided.
        """
        rows = self.query(format_id=format_id, limit=limit)

        if path:
            export_to_file(rows, path, fmt=fmt)
            return path

        if fmt == "csv":
            return export_csv(rows)
        else:
            return export_json(rows)

    # ── Deletion ──────────────────────────────────────────────────────────────

    def delete(self, hashaxe_id: int) -> bool:
        """Delete a single hashaxe result by ID."""
        conn = self._connect()
        try:
            cursor = conn.execute("DELETE FROM cracks WHERE id = ?", (hashaxe_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def clear_all(self) -> int:
        """Delete ALL hashaxe results. USE WITH CAUTION.

        Returns:
            Number of rows deleted.
        """
        conn = self._connect()
        try:
            cursor = conn.execute("DELETE FROM cracks")
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    # ── Display helpers ───────────────────────────────────────────────────────

    def format_results_table(
        self,
        rows: list[dict[str, Any]] | None = None,
        limit: int = 20,
    ) -> str:
        """Format results as a pretty ASCII table for terminal display.

        Args:
            rows: Pre-fetched rows, or None to query latest.
            limit: Max rows if querying.

        Returns:
            Formatted table string.
        """
        if rows is None:
            rows = self.query(limit=limit)

        if not rows:
            return "  No results found."

        lines: list[str] = []
        lines.append(
            f"  {'ID':>4}  {'Timestamp':<20}  {'Format':<18}  "
            f"{'Password':<24}  {'Speed':>10}  {'Time':>8}"
        )
        lines.append("  " + "─" * 94)

        for r in rows:
            pw = r.get("passphrase", "???")
            if len(pw) > 22:
                pw = pw[:20] + ".."
            speed = r.get("speed_pw_s", 0)
            speed_str = f"{speed:,.0f} pw/s" if speed else "—"
            elapsed = r.get("elapsed_sec", 0)
            if elapsed < 60:
                time_str = f"{elapsed:.1f}s"
            elif elapsed < 3600:
                time_str = f"{elapsed/60:.1f}m"
            else:
                time_str = f"{elapsed/3600:.1f}h"
            ts = r.get("timestamp", "")[:19]

            lines.append(
                f"  {r.get('id', 0):>4}  {ts:<20}  "
                f"{r.get('format_id', ''):<18}  {pw:<24}  "
                f"{speed_str:>10}  {time_str:>8}"
            )

        lines.append(f"\n  Total: {len(rows)} result(s)")
        return "\n".join(lines)

    def format_stats(self) -> str:
        """Format stats as a pretty terminal display."""
        s = self.stats()

        if s["total_cracks"] == 0:
            return "  No cracks logged yet."

        lines: list[str] = []
        lines.append(f"  Total Cracks      : {s['total_cracks']:,}")
        lines.append(f"  Unique Passwords  : {s['unique_passwords']:,}")
        lines.append(f"  Total Candidates  : {s['total_candidates']:,}")
        lines.append(f"  Avg Speed         : {s['avg_speed_pw_s']:,.1f} pw/s")

        if s["fastest_hashaxe_sec"] is not None:
            lines.append(f"  Fastest Hashaxe     : {s['fastest_hashaxe_sec']:.2f}s")
        if s["slowest_hashaxe_sec"] is not None:
            lines.append(f"  Slowest Hashaxe     : {s['slowest_hashaxe_sec']:.2f}s")

        lines.append(f"  Formats Cracked   : {', '.join(s['formats'])}")

        if s["by_format"]:
            lines.append("")
            lines.append("  Per-Format Breakdown:")
            for fmt, data in s["by_format"].items():
                lines.append(
                    f"    {fmt:<20}  "
                    f"{data.get('count', 0):>4} cracks  "
                    f"avg {data.get('avg_speed', 0):,.0f} pw/s"
                )

        return "\n".join(lines)
