# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/db/__init__.py
#  Results database package for permanent hashaxe result logging and statistics.
#  Provides SQLite storage, CRUD operations, queries, and CSV/JSON export.
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
Hashaxe V3 — Results Database Package

Every cracked password is logged forever. Query, filter, export, and
aggregate statistics from the command line.

Components:
  - schema.py   — SQLite table definitions & migrations
  - manager.py  — CrackDB class (CRUD, queries, stats)
  - export.py   — CSV / JSON export

Storage: ~/.shadowhashaxe/results.db  (auto-created)

GANGA Offensive Ops · Bhanu Guragain
"""
from __future__ import annotations

from hashaxe.db.export import export_csv, export_json
from hashaxe.db.manager import CrackDB
from hashaxe.db.schema import DB_VERSION, SCHEMA_SQL

__all__ = ["DB_VERSION", "SCHEMA_SQL", "CrackDB", "export_csv", "export_json"]
