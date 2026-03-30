# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_auto_pwn_api_tui.py
#  Tests for Auto-Pwn orchestrator, FastAPI REST server, and TUI dashboard.
#  Covers pipeline execution, API endpoints, and rendering safety.
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
tests/test_auto_pwn_api_tui.py — Tests for production finalization features.

Covers:
  - Auto-Pwn Orchestrator pipeline
  - Headless FastAPI REST Server endpoints
  - TUI Dashboard rendering safety
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from hashaxe.api import _JOBS, _RESULTS, app
from hashaxe.auto_pwn import AutoPwnOrchestrator
from hashaxe.tui.app import Dashboard

client = TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════════
# Auto-Pwn Orchestrator Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAutoPwnOrchestrator:

    def test_init_orchestrator(self):
        auto_pwn = AutoPwnOrchestrator("hash.txt", "words.txt")
        assert auto_pwn.osint_path is None
        assert auto_pwn.max_duration == 3600

    def test_pipeline_fast_wordlist_success(self):
        auto_pwn = AutoPwnOrchestrator("hash.txt", "words.txt")
        with patch.object(
            auto_pwn, "_stage_fast_wordlist", return_value="autopwn_fixture_3j"
        ) as mock_stage:
            result = auto_pwn.execute_pipeline()
            assert result == "autopwn_fixture_3j"
            mock_stage.assert_called_once()

    @patch("hashaxe.auto_pwn.hashaxe")
    def test_pipeline_exhaustion_failure(self, hashaxe_mock):
        hashaxe_mock.return_value = None

        auto_pwn = AutoPwnOrchestrator("hash.txt", "words.txt")
        result = auto_pwn.execute_pipeline()
        assert result is None
        assert hashaxe_mock.call_count == 3  # wordlist, PCFG, Hybrid

    @patch("hashaxe.auto_pwn.hashaxe")
    def test_pipeline_time_expiry(self, hashaxe_mock):
        hashaxe_mock.return_value = None

        # 0 max duration = immediate expiration after stage 1
        auto_pwn = AutoPwnOrchestrator("hash.txt", "words.txt", max_duration_sec=0)
        result = auto_pwn.execute_pipeline()
        assert result is None
        assert hashaxe_mock.call_count == 1  # only stage 1 runs


# ═══════════════════════════════════════════════════════════════════════════════
# REST API Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRESTAPI:

    def setup_method(self):
        _JOBS.clear()
        _RESULTS.clear()

    @patch("hashaxe.cracker.hashaxe")
    def test_read_root(self, hashaxe_mock):
        response = client.get("/")
        assert response.status_code == 200
        assert "v1.0.0" in response.json()["status"]

    @patch("hashaxe.cracker.hashaxe")
    def test_submit_job(self, hashaxe_mock):
        hashaxe_mock.return_value = "autopwn_fixture_3j"
        req = {
            "target": "5d41402abc4b2a76b9719d911017c592",
            "target_type": "hash",
            "hash_algorithm": "md5",
            "attack_mode": "auto_pwn",
        }
        response = client.post("/jobs", json=req)
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert data["status"] == "queued"

    @patch("hashaxe.cracker.hashaxe")
    def test_get_job_status_not_found(self, hashaxe_mock):
        response = client.get("/jobs/nonexistent-id")
        assert response.status_code == 404

    @patch("hashaxe.cracker.hashaxe")
    def test_get_job_status(self, hashaxe_mock):
        hashaxe_mock.return_value = "autopwn_fixture_3j"
        req = {"target": "hash123"}
        post_response = client.post("/jobs", json=req)
        job_id = post_response.json()["job_id"]

        get_response = client.get(f"/jobs/{job_id}")
        assert get_response.status_code == 200
        data = get_response.json()
        assert data["job_id"] == job_id
        assert data["status"] in ("queued", "running", "completed")

    @patch("hashaxe.cracker.hashaxe")
    def test_cancel_job(self, hashaxe_mock):
        hashaxe_mock.return_value = None
        req = {"target": "hash123"}
        post_response = client.post("/jobs", json=req)
        job_id = post_response.json()["job_id"]

        del_response = client.delete(f"/jobs/{job_id}")
        assert del_response.status_code == 200
        assert _JOBS[job_id]["status"] == "cancelled"

    @patch("hashaxe.cracker.hashaxe")
    def test_cancel_job_not_found(self, hashaxe_mock):
        response = client.delete("/jobs/fake-id")
        assert response.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════════
# TUI Dashboard Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestTUIDashboard:

    def test_dashboard_init(self):
        monitor_mock = MagicMock()
        dash = Dashboard(monitor_mock)
        assert dash.title == "Hashaxe V1 Dashboard"
        assert dash.layout is not None
        assert dash.layout.name == "root"

    def test_dashboard_generate_panels(self):
        monitor_mock = MagicMock()
        monitor_mock.snapshot.return_value = {
            "algorithm": "SHA-256",
            "attack_mode": "Auto-Pwn",
            "rolling_speed": 5000000.0,
            "keyspace_checked": 1000,
            "keyspace_total": 10000,
        }
        dash = Dashboard(monitor_mock)

        # Test panel generation logic functions without erroring
        header = dash._generate_header()
        progress = dash._generate_progress()
        cluster = dash._generate_cluster_health()
        info = dash._generate_info()
        footer = dash._generate_footer()

        assert header is not None
        assert progress is not None

    def test_dashboard_update_layout(self):
        monitor_mock = MagicMock()
        monitor_mock.snapshot.return_value = {}
        dash = Dashboard(monitor_mock)
        dash._update_layout()  # Ensure it doesn't throw
