# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/db/export.py
#  CSV and JSON export utilities for cracked results database.
#  Provides functions to export CrackDB query results to various formats.
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
CSV and JSON export for cracked results.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from typing import Any


def export_csv(rows: Sequence[dict[str, Any]], columns: Sequence[str] | None = None) -> str:
    """Export rows to CSV string.

    Args:
        rows: List of dicts from CrackDB.query().
        columns: Optional column filter. None = all columns.

    Returns:
        CSV string with header row.
    """
    if not rows:
        return ""

    if columns is None:
        columns = list(rows[0].keys())

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    return buf.getvalue()


def export_json(
    rows: Sequence[dict[str, Any]],
    indent: int = 2,
    columns: Sequence[str] | None = None,
) -> str:
    """Export rows to JSON string.

    Args:
        rows: List of dicts from CrackDB.query().
        indent: JSON indentation (default 2).
        columns: Optional column filter. None = all columns.

    Returns:
        Pretty-printed JSON array string.
    """
    if not rows:
        return "[]"

    if columns is not None:
        filtered = []
        for row in rows:
            filtered.append({k: v for k, v in row.items() if k in columns})
        rows = filtered

    return json.dumps(list(rows), indent=indent, default=str)


def export_to_file(
    rows: Sequence[dict[str, Any]],
    path: str,
    fmt: str = "json",
    columns: Sequence[str] | None = None,
) -> int:
    """Export rows to a file.

    Args:
        rows: List of dicts from CrackDB.query().
        path: Output file path.
        fmt: 'json' or 'csv'.
        columns: Optional column filter.

    Returns:
        Number of rows exported.
    """
    if fmt == "csv":
        content = export_csv(rows, columns)
    else:
        content = export_json(rows, columns=columns)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    return len(rows)
