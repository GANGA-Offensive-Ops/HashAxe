# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/db/schema.py
#  SQLite schema definition for Hashaxe results database.
#  Defines tables for cracks metadata and schema version tracking.
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
SQLite schema for the Hashaxe results database.

Tables:
  cracks — Every successful hashaxe is logged with full metadata.
  meta   — Schema version for forward migrations.

Indexes:
  idx_cracks_timestamp  — Fast chronological queries
  idx_cracks_format     — Fast format-based filtering
  idx_cracks_hash       — Fast duplicate detection
"""
from __future__ import annotations

DB_VERSION = 1

SCHEMA_SQL = """
-- ═══════════════════════════════════════════════════════════════════════════════
-- Hashaxe V3 Results Database — Schema v1
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS meta (
    key     TEXT    PRIMARY KEY,
    value   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS cracks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Timing
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),

    -- Source
    source_path     TEXT,                   -- Original file path or 'inline'
    source_hash     TEXT,                   -- SHA-256 of the original input (dedup)

    -- Format
    format_id       TEXT    NOT NULL,       -- e.g. 'hash.md5', 'ssh.openssh'
    format_name     TEXT,                   -- e.g. 'MD5', 'OpenSSH RSA'
    hash_preview    TEXT,                   -- First 32 chars of the hash/target

    -- Result
    passphrase      TEXT    NOT NULL,       -- The cracked password
    passphrase_hex  TEXT,                   -- Hex-encoded for binary passphrases

    -- Attack metadata
    attack_mode     TEXT    DEFAULT 'wordlist',  -- wordlist, mask, hybrid, rules, etc.
    wordlist_path   TEXT,                   -- Path to wordlist used
    rule_file       TEXT,                   -- Rule file if any
    mask_pattern    TEXT,                   -- Mask pattern if any

    -- Performance
    candidates      INTEGER DEFAULT 0,     -- Total passwords tried
    elapsed_sec     REAL    DEFAULT 0.0,   -- Time to hashaxe (seconds)
    speed_pw_s      REAL    DEFAULT 0.0,   -- Average speed (pw/s)

    -- Hardware
    tool_version    TEXT,                   -- Hashaxe version
    cpu_model       TEXT,                   -- CPU model string
    gpu_model       TEXT,                   -- GPU model string (if used)
    workers         INTEGER DEFAULT 1,     -- Number of worker processes

    -- Notes
    notes           TEXT                    -- User-added notes
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_cracks_timestamp ON cracks(timestamp);
CREATE INDEX IF NOT EXISTS idx_cracks_format    ON cracks(format_id);
CREATE INDEX IF NOT EXISTS idx_cracks_hash      ON cracks(source_hash);
CREATE INDEX IF NOT EXISTS idx_cracks_source    ON cracks(source_path);
"""

MIGRATION_V2 = """
-- Reserved for future schema upgrades
-- ALTER TABLE cracks ADD COLUMN session_id TEXT;
"""
