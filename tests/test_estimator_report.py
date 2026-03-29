# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_estimator_report.py
#  Tests for keyspace estimator and report generator functionality.
#  Covers ETA calculation, keyspace estimation, and report formatting.
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
Tests for Estimator and Report Generator.
"""
from __future__ import annotations

import pytest


class TestEstimator:
    def test_md5_gpu_mid_instant(self):
        from hashaxe.identify.estimator import KEYSPACE, estimate_time

        est = estimate_time("hash.md5", KEYSPACE["rockyou"], "gpu_mid")
        assert est.estimated_seconds < 1  # rockyou on MD5 = instant
        assert est.feasible is True

    def test_bcrypt_is_slow(self):
        from hashaxe.identify.estimator import KEYSPACE, estimate_time

        est = estimate_time("hash.bcrypt", KEYSPACE["rockyou"], "cpu")
        # bcrypt @500 h/s with 14M candidates = ~28000 seconds (hours)
        assert est.estimated_seconds > 1000
        assert "hours" in est.estimated_human or "minutes" in est.estimated_human

    def test_argon2_extreme(self):
        from hashaxe.identify.estimator import KEYSPACE, estimate_time

        est = estimate_time("hash.argon2", KEYSPACE["8char_full"], "cpu")
        # argon2 @10 h/s with ~6.6e15 keys = centuries
        assert "years" in est.estimated_human or "centuries" in est.estimated_human
        assert est.feasible is False

    def test_comparison(self):
        from hashaxe.identify.estimator import estimate_comparison

        results = estimate_comparison("hash.md5")
        assert "cpu" in results
        assert "gpu_mid" in results
        assert "gpu_high" in results
        # GPU should be faster than CPU
        assert results["gpu_high"].estimated_seconds < results["cpu"].estimated_seconds

    def test_unknown_format_fallback(self):
        from hashaxe.identify.estimator import estimate_time

        est = estimate_time("unknown.format", 1000)
        assert est.estimated_seconds > 0


class TestReportGenerator:
    def test_basic_report(self):
        from hashaxe.identify.report import CrackResult, ReportConfig, generate_report

        results = [
            CrackResult(
                hash_value="5d41402abc4b2a76b9719d911017c592",
                format_id="hash.md5",
                algorithm="MD5",
                hashaxeed=True,
                password="hello",
                time_taken=0.1,
                attack_mode="wordlist",
                hashcat_mode=0,
            ),
        ]
        config = ReportConfig(title="Test Report", date="2026-03-13")
        report = generate_report(results, config)
        assert "Test Report" in report
        assert "MD5" in report
        assert "hello" in report
        assert "1/1" in report

    def test_mitre_included(self):
        from hashaxe.identify.report import CrackResult, generate_report

        results = [
            CrackResult(
                hash_value="test",
                format_id="network.krb5tgs_rc4",
                algorithm="Kerberoast",
                hashaxeed=True,
                password="Password1",
                hashcat_mode=13100,
            ),
        ]
        report = generate_report(results)
        assert "T1558" in report
        assert "MITRE" in report

    def test_remediation_included(self):
        from hashaxe.identify.report import CrackResult, generate_report

        results = [
            CrackResult(
                hash_value="test",
                format_id="hash.md5",
                algorithm="MD5",
                hashcat_mode=0,
            ),
        ]
        report = generate_report(results)
        assert "Remediation" in report
        assert "bcrypt" in report.lower() or "argon2" in report.lower()

    def test_no_hashaxeed_report(self):
        from hashaxe.identify.report import CrackResult, generate_report

        results = [
            CrackResult(
                hash_value="test",
                format_id="hash.bcrypt",
                algorithm="bcrypt",
                hashaxeed=False,
                hashcat_mode=3200,
            ),
        ]
        report = generate_report(results)
        assert "No passwords were recovered" in report

    def test_empty_results(self):
        from hashaxe.identify.report import generate_report

        report = generate_report([])
        assert "0" in report
