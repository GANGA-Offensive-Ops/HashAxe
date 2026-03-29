# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_db.py
#  Tests for CrackDB results database with SQLite storage.
#  Covers schema, CRUD operations, queries, stats, and CSV/JSON export.
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
Tests for Batch 3: Results Database (CrackDB).

Coverage:
  - Schema initialization (table creation, indexes)
  - log_hashaxe() insertion
  - query() with filters
  - count()
  - stats() aggregation
  - export_csv / export_json
  - export_to_file
  - delete / clear_all
  - format_results_table / format_stats display
  - Potfile append
  - Duplicate logging
  - Edge cases (empty DB, large datasets)

GANGA Offensive Ops · Crack V3
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestSchema(unittest.TestCase):
    """Test SQLite schema creation."""

    def test_schema_creates_tables(self):
        from hashaxe.db.manager import CrackDB
        with tempfile.TemporaryDirectory() as td:
            CrackDB(db_path=Path(td) / "test.db")
            # Should not raise
            self.assertTrue((Path(td) / "test.db").exists())

    def test_schema_version_stored(self):
        import sqlite3

        from hashaxe.db.manager import CrackDB
        from hashaxe.db.schema import DB_VERSION
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test.db"
            CrackDB(db_path=db_path)
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            conn.close()
            self.assertEqual(row["value"], str(DB_VERSION))

    def test_schema_idempotent(self):
        from hashaxe.db.manager import CrackDB
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test.db"
            # Create twice — should not raise
            CrackDB(db_path=db_path)
            CrackDB(db_path=db_path)


class TestLogCrack(unittest.TestCase):
    """Test hashaxe logging."""

    def _make_db(self):
        self._td = tempfile.mkdtemp()
        from hashaxe.db.manager import CrackDB
        return CrackDB(db_path=Path(self._td) / "test.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def test_log_returns_id(self):
        db = self._make_db()
        row_id = db.log_hashaxe(
            format_id="hash.md5",
            passphrase="db_test_fixture_4k",
            source_path="test.txt",
        )
        self.assertIsInstance(row_id, int)
        self.assertGreater(row_id, 0)

    def test_log_with_all_fields(self):
        db = self._make_db()
        row_id = db.log_hashaxe(
            format_id="hash.sha256",
            passphrase="admin",
            source_path="/tmp/hashes.txt",
            format_name="SHA-256",
            hash_preview="5e884898da2802...",
            attack_mode="wordlist+rules",
            wordlist_path="test_files/password.txt",  # Relative path for portability
            rule_file="best64.rule",
            mask_pattern=None,
            candidates=1337000,
            elapsed_sec=42.5,
            speed_pw_s=31458.8,
            workers=8,
            gpu_model="NVIDIA RTX 4090",
            notes="Found during CTF",
        )
        result = db.get_by_id(row_id)
        self.assertIsNotNone(result)
        self.assertEqual(result["format_id"], "hash.sha256")
        self.assertEqual(result["passphrase"], "admin")
        self.assertEqual(result["candidates"], 1337000)
        self.assertEqual(result["workers"], 8)
        self.assertEqual(result["gpu_model"], "NVIDIA RTX 4090")

    def test_log_multiple(self):
        db = self._make_db()
        id1 = db.log_hashaxe(format_id="hash.md5", passphrase="pw1")
        id2 = db.log_hashaxe(format_id="hash.sha1", passphrase="pw2")
        id3 = db.log_hashaxe(format_id="hash.md5", passphrase="pw3")
        self.assertEqual(id2, id1 + 1)
        self.assertEqual(id3, id2 + 1)

    def test_potfile_created(self):
        db = self._make_db()
        db.log_hashaxe(format_id="hash.md5", passphrase="test_pw")
        potfile = Path(self._td) / "passwords.txt"
        self.assertTrue(potfile.exists())
        content = potfile.read_text()
        self.assertIn("hash.md5", content)
        self.assertIn("test_pw", content)


class TestQuery(unittest.TestCase):
    """Test query and filtering."""

    def _make_db_with_data(self):
        self._td = tempfile.mkdtemp()
        from hashaxe.db.manager import CrackDB
        db = CrackDB(db_path=Path(self._td) / "test.db")
        db.log_hashaxe(format_id="hash.md5", passphrase="pw1", source_path="a.txt", candidates=100, elapsed_sec=0.1, speed_pw_s=1000)
        db.log_hashaxe(format_id="hash.sha256", passphrase="pw2", source_path="b.txt", candidates=5000, elapsed_sec=2.5, speed_pw_s=2000)
        db.log_hashaxe(format_id="hash.md5", passphrase="pw3", source_path="a.txt", candidates=200, elapsed_sec=0.2, speed_pw_s=1000)
        db.log_hashaxe(format_id="hash.bcrypt", passphrase="pw4", source_path="c.txt", candidates=50, elapsed_sec=30.0, speed_pw_s=1.67)
        return db

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def test_query_all(self):
        db = self._make_db_with_data()
        results = db.query()
        self.assertEqual(len(results), 4)

    def test_query_by_format(self):
        db = self._make_db_with_data()
        results = db.query(format_id="hash.md5")
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertEqual(r["format_id"], "hash.md5")

    def test_query_by_source(self):
        db = self._make_db_with_data()
        results = db.query(source_path="a.txt")
        self.assertEqual(len(results), 2)

    def test_query_by_passphrase(self):
        db = self._make_db_with_data()
        results = db.query(passphrase="pw2")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["format_id"], "hash.sha256")

    def test_query_limit(self):
        db = self._make_db_with_data()
        results = db.query(limit=2)
        self.assertEqual(len(results), 2)

    def test_query_empty_result(self):
        db = self._make_db_with_data()
        results = db.query(format_id="hash.nonexistent")
        self.assertEqual(len(results), 0)

    def test_count_all(self):
        db = self._make_db_with_data()
        self.assertEqual(db.count(), 4)

    def test_count_by_format(self):
        db = self._make_db_with_data()
        self.assertEqual(db.count(format_id="hash.md5"), 2)
        self.assertEqual(db.count(format_id="hash.bcrypt"), 1)

    def test_get_by_id(self):
        db = self._make_db_with_data()
        result = db.get_by_id(1)
        self.assertIsNotNone(result)
        self.assertEqual(result["passphrase"], "pw1")

    def test_get_by_id_nonexistent(self):
        db = self._make_db_with_data()
        result = db.get_by_id(999)
        self.assertIsNone(result)


class TestStats(unittest.TestCase):
    """Test aggregate statistics."""

    _td: str | None = None

    def _make_db_with_data(self):
        self._td = tempfile.mkdtemp()
        from hashaxe.db.manager import CrackDB
        db = CrackDB(db_path=Path(self._td) / "test.db")
        db.log_hashaxe(format_id="hash.md5", passphrase="pw1", candidates=100, elapsed_sec=0.1, speed_pw_s=1000)
        db.log_hashaxe(format_id="hash.sha256", passphrase="pw2", candidates=5000, elapsed_sec=2.5, speed_pw_s=2000)
        db.log_hashaxe(format_id="hash.md5", passphrase="pw3", candidates=200, elapsed_sec=0.2, speed_pw_s=1000)
        return db

    def tearDown(self):
        import shutil
        if self._td:
            shutil.rmtree(self._td, ignore_errors=True)

    def test_stats_total(self):
        db = self._make_db_with_data()
        s = db.stats()
        self.assertEqual(s["total_hashaxes"], 3)

    def test_stats_formats(self):
        db = self._make_db_with_data()
        s = db.stats()
        self.assertIn("hash.md5", s["formats"])
        self.assertIn("hash.sha256", s["formats"])

    def test_stats_fastest(self):
        db = self._make_db_with_data()
        s = db.stats()
        self.assertAlmostEqual(s["fastest_hashaxe_sec"], 0.1, places=1)

    def test_stats_unique_passwords(self):
        db = self._make_db_with_data()
        s = db.stats()
        self.assertEqual(s["unique_passwords"], 3)

    def test_stats_by_format(self):
        db = self._make_db_with_data()
        s = db.stats()
        self.assertIn("hash.md5", s["by_format"])
        self.assertEqual(s["by_format"]["hash.md5"]["count"], 2)

    def test_stats_empty_db(self):
        from hashaxe.db.manager import CrackDB
        with tempfile.TemporaryDirectory() as td:
            db = CrackDB(db_path=Path(td) / "test.db")
            s = db.stats()
            self.assertEqual(s["total_hashaxes"], 0)


class TestExport(unittest.TestCase):
    """Test CSV and JSON export."""

    _td: str | None = None

    def _make_db_with_data(self):
        self._td = tempfile.mkdtemp()
        from hashaxe.db.manager import CrackDB
        db = CrackDB(db_path=Path(self._td) / "test.db")
        db.log_hashaxe(format_id="hash.md5", passphrase="pw1", candidates=100)
        db.log_hashaxe(format_id="hash.sha256", passphrase="pw2", candidates=5000)
        return db

    def tearDown(self):
        import shutil
        if self._td:
            shutil.rmtree(self._td, ignore_errors=True)

    def test_export_json_string(self):
        db = self._make_db_with_data()
        output = db.export(fmt="json")
        data = json.loads(output)
        self.assertEqual(len(data), 2)
        self.assertIn("passphrase", data[0])

    def test_export_csv_string(self):
        db = self._make_db_with_data()
        output = db.export(fmt="csv")
        lines = output.strip().split("\n")
        self.assertEqual(len(lines), 3)  # header + 2 rows
        self.assertIn("format_id", lines[0])

    def test_export_json_file(self):
        db = self._make_db_with_data()
        outpath = os.path.join(self._td, "results.json")
        db.export(fmt="json", path=outpath)
        self.assertTrue(os.path.exists(outpath))
        data = json.loads(Path(outpath).read_text())
        self.assertEqual(len(data), 2)

    def test_export_csv_file(self):
        db = self._make_db_with_data()
        outpath = os.path.join(self._td, "results.csv")
        db.export(fmt="csv", path=outpath)
        self.assertTrue(os.path.exists(outpath))
        lines = Path(outpath).read_text().strip().split("\n")
        self.assertGreaterEqual(len(lines), 3)

    def test_export_with_format_filter(self):
        db = self._make_db_with_data()
        output = db.export(fmt="json", format_id="hash.md5")
        data = json.loads(output)
        self.assertEqual(len(data), 1)

    def test_export_empty_db(self):
        from hashaxe.db.manager import CrackDB
        with tempfile.TemporaryDirectory() as td:
            db = CrackDB(db_path=Path(td) / "test.db")
            self.assertEqual(db.export(fmt="json"), "[]")
            self.assertEqual(db.export(fmt="csv"), "")


class TestDelete(unittest.TestCase):
    """Test deletion operations."""

    def _make_db_with_data(self):
        self._td = tempfile.mkdtemp()
        from hashaxe.db.manager import CrackDB
        db = CrackDB(db_path=Path(self._td) / "test.db")
        db.log_hashaxe(format_id="hash.md5", passphrase="pw1")
        db.log_hashaxe(format_id="hash.sha256", passphrase="pw2")
        db.log_hashaxe(format_id="hash.md5", passphrase="pw3")
        return db

    def tearDown(self):
        import shutil
        shutil.rmtree(self._td, ignore_errors=True)

    def test_delete_by_id(self):
        db = self._make_db_with_data()
        self.assertTrue(db.delete(1))
        self.assertEqual(db.count(), 2)
        self.assertIsNone(db.get_by_id(1))

    def test_delete_nonexistent(self):
        db = self._make_db_with_data()
        self.assertFalse(db.delete(999))
        self.assertEqual(db.count(), 3)

    def test_clear_all(self):
        db = self._make_db_with_data()
        deleted = db.clear_all()
        self.assertEqual(deleted, 3)
        self.assertEqual(db.count(), 0)


class TestDisplay(unittest.TestCase):
    """Test formatted display output."""

    _td: str | None = None

    def _make_db_with_data(self):
        self._td = tempfile.mkdtemp()
        from hashaxe.db.manager import CrackDB
        db = CrackDB(db_path=Path(self._td) / "test.db")
        db.log_hashaxe(format_id="hash.md5", passphrase="db_test_fixture_4k", candidates=50000, elapsed_sec=0.5, speed_pw_s=100000)
        db.log_hashaxe(format_id="hash.bcrypt", passphrase="admin", candidates=300, elapsed_sec=120.0, speed_pw_s=2.5)
        return db

    def tearDown(self):
        import shutil
        if self._td:
            shutil.rmtree(self._td, ignore_errors=True)

    def test_format_results_table(self):
        db = self._make_db_with_data()
        table = db.format_results_table()
        self.assertIn("db_test_fixture_4k", table)
        self.assertIn("hash.md5", table)
        self.assertIn("Total: 2", table)

    def test_format_results_empty(self):
        from hashaxe.db.manager import CrackDB
        with tempfile.TemporaryDirectory() as td:
            db = CrackDB(db_path=Path(td) / "test.db")
            table = db.format_results_table()
            self.assertIn("No results", table)

    def test_format_stats(self):
        db = self._make_db_with_data()
        output = db.format_stats()
        self.assertIn("Total Cracks", output)
        self.assertIn("hash.md5", output)

    def test_format_stats_empty(self):
        from hashaxe.db.manager import CrackDB
        with tempfile.TemporaryDirectory() as td:
            db = CrackDB(db_path=Path(td) / "test.db")
            output = db.format_stats()
            self.assertIn("No hashaxes logged", output)


class TestExportModule(unittest.TestCase):
    """Test the export module directly."""

    def test_export_csv_empty(self):
        from hashaxe.db.export import export_csv
        self.assertEqual(export_csv([]), "")

    def test_export_json_empty(self):
        from hashaxe.db.export import export_json
        self.assertEqual(export_json([]), "[]")

    def test_export_csv_with_columns(self):
        from hashaxe.db.export import export_csv
        rows = [{"a": 1, "b": 2, "c": 3}]
        result = export_csv(rows, columns=["a", "b"])
        self.assertIn("a,b", result)
        self.assertNotIn("c", result)

    def test_export_json_with_columns(self):
        from hashaxe.db.export import export_json
        rows = [{"a": 1, "b": 2, "c": 3}]
        result = export_json(rows, columns=["a", "b"])
        data = json.loads(result)
        self.assertIn("a", data[0])
        self.assertNotIn("c", data[0])


if __name__ == "__main__":
    unittest.main()
