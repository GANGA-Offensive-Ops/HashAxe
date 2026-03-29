# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_monitor_healing.py
#  Tests for performance monitor and distributed worker health management.
#  Covers metrics recording, ETA calculation, heartbeat, and dead worker detection.
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
tests/test_monitor_healing.py — Tests for Performance Monitor and Distributed Healing.

Tests:
  - PerformanceMonitor: recording, snapshot, speed, ETA, duration formatting
  - WorkerHealthManager: registration, heartbeat, dead detection, re-queuing
  - WorkerHealth: scoring, failure tracking
"""
from __future__ import annotations

import time

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# Performance Monitor Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPerformanceMonitor:

    def test_start_stop(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor(total_keyspace=1000)
        mon.start()
        assert mon.is_running
        mon.stop()
        assert not mon.is_running

    def test_record_and_snapshot(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor(total_keyspace=1000, hash_type="md5")
        mon.start()
        mon.record(tried=100)
        snap = mon.snapshot()
        assert snap["tried"] == 100
        assert snap["hash_type"] == "md5"
        assert snap["keyspace"] == 1000
        mon.stop()

    def test_multiple_records(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor(total_keyspace=1000)
        mon.start()
        mon.record(tried=100)
        mon.record(tried=200)
        mon.record(tried=50)
        assert mon.snapshot()["tried"] == 350
        mon.stop()

    def test_progress_percentage(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor(total_keyspace=1000)
        mon.start()
        mon.record(tried=500)
        snap = mon.snapshot()
        assert snap["progress_pct"] == 50.0
        mon.stop()

    def test_multiple_workers(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor()
        mon.start()
        mon.record(tried=100, worker_id="w1")
        mon.record(tried=200, worker_id="w2")
        snap = mon.snapshot()
        assert snap["workers"] == 2
        assert snap["tried"] == 300
        mon.stop()

    def test_gpu_utilization(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor()
        mon.start()
        mon.record(tried=300, on_gpu=True)
        mon.record(tried=100, on_gpu=False)
        snap = mon.snapshot()
        assert snap["gpu_pct"] == 75.0
        mon.stop()

    def test_record_match(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor()
        mon.start()
        mon.record(tried=1000)
        mon.record_match(5)
        snap = mon.snapshot()
        assert snap["matched"] == 5
        assert snap["hit_rate"] == 0.005
        mon.stop()

    def test_format_report(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor(total_keyspace=10000, hash_type="sha256")
        mon.start()
        mon.record(tried=5000)
        report = mon.format_report()
        assert "sha256" in report
        assert "5,000" in report
        mon.stop()

    def test_worker_stats(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor()
        mon.start()
        mon.record(tried=100, worker_id="worker_a")
        stats = mon.worker_stats()
        assert len(stats) == 1
        assert stats[0]["id"] == "worker_a"
        assert stats[0]["tried"] == 100
        mon.stop()

    def test_export_benchmark(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor(hash_type="bcrypt")
        mon.start()
        mon.record(tried=1000)
        export = mon.export_benchmark()
        assert export["hash_type"] == "bcrypt"
        assert export["total_tried"] == 1000
        assert "timestamp" in export
        mon.stop()

    def test_duration_formatting(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor()
        assert mon._format_duration(30) == "30.0s"
        assert mon._format_duration(90) == "1m 30s"
        assert mon._format_duration(3700) == "1h 1m"
        assert mon._format_duration(90000) == "1d 1h"

    def test_zero_keyspace(self):
        from hashaxe.monitor import PerformanceMonitor

        mon = PerformanceMonitor(total_keyspace=0)
        mon.start()
        mon.record(tried=100)
        snap = mon.snapshot()
        assert snap["progress_pct"] == 0
        assert snap["eta_str"] == "N/A"
        mon.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Worker Health Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerHealth:

    def test_initial_health(self):
        from hashaxe.distributed.healing import WorkerHealth

        w = WorkerHealth(worker_id="w1")
        assert w.is_alive
        assert w.health_score == 1.0

    def test_heartbeat_updates(self):
        from hashaxe.distributed.healing import WorkerHealth

        w = WorkerHealth(worker_id="w1")
        old_hb = w.last_heartbeat
        time.sleep(0.01)
        w.update_heartbeat()
        assert w.last_heartbeat > old_hb

    def test_completion_tracking(self):
        from hashaxe.distributed.healing import WorkerHealth

        w = WorkerHealth(worker_id="w1")
        w.record_completion(tried=1000, speed=500.0)
        assert w.total_jobs_completed == 1
        assert w.total_tried == 1000
        assert w.avg_speed == 500.0

    def test_failure_tracking(self):
        from hashaxe.distributed.healing import WorkerHealth

        w = WorkerHealth(worker_id="w1")
        w.record_completion(tried=1000, speed=500.0)
        w.record_failure()
        assert w.total_jobs_failed == 1
        assert w.consecutive_failures == 1
        assert w.health_score < 1.0

    def test_health_score_degrades(self):
        from hashaxe.distributed.healing import WorkerHealth

        w = WorkerHealth(worker_id="w1")
        w.record_completion(tried=1000, speed=100.0)
        score_after_success = w.health_score
        w.record_failure()
        w.record_failure()
        w.record_failure()
        assert w.health_score < score_after_success

    def test_heartbeat_resets_failures(self):
        from hashaxe.distributed.healing import WorkerHealth

        w = WorkerHealth(worker_id="w1")
        w.record_failure()
        w.record_failure()
        assert w.consecutive_failures == 2
        w.update_heartbeat()
        assert w.consecutive_failures == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Worker Health Manager Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerHealthManager:

    def test_register_worker(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager()
        mgr.register_worker("w1", host="192.168.1.10", gpu="RTX 3050")
        status = mgr.cluster_status()
        assert status["total_workers"] == 1
        assert status["alive"] == 1

    def test_heartbeat(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager()
        mgr.register_worker("w1")
        mgr.heartbeat("w1")
        status = mgr.cluster_status()
        assert status["alive"] == 1

    def test_track_and_complete_job(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager()
        mgr.register_worker("w1")
        mgr.track_job("job_001", "w1", {"data": "test"})
        assert mgr.cluster_status()["in_flight_jobs"] == 1
        mgr.complete_job("job_001", tried=100, speed=50.0)
        assert mgr.cluster_status()["in_flight_jobs"] == 0

    def test_fail_job_returns_data(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager()
        mgr.register_worker("w1")
        mgr.track_job("job_001", "w1", {"chunk": "0-1000"})
        data = mgr.fail_job("job_001")
        assert data == {"chunk": "0-1000"}

    def test_dead_worker_detection(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager(heartbeat_timeout=0.05)
        mgr.register_worker("w1")
        mgr.track_job("job_001", "w1", {"chunk": "test"})
        # Simulate timeout
        time.sleep(0.1)
        requeued = mgr.check_health()
        assert len(requeued) >= 1
        status = mgr.cluster_status()
        assert status["dead"] >= 1

    def test_best_workers(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager()
        mgr.register_worker("w1")
        mgr.register_worker("w2")
        mgr.register_worker("w3")
        best = mgr.best_workers(n=2)
        assert len(best) == 2

    def test_cluster_status_shape(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager()
        mgr.register_worker("w1", host="box1", gpu="RTX")
        status = mgr.cluster_status()
        assert "total_workers" in status
        assert "alive" in status
        assert "dead" in status
        assert "workers" in status
        assert len(status["workers"]) == 1
        assert status["workers"][0]["host"] == "box1"

    def test_stale_job_requeue(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager(stale_job_timeout=0.05)
        mgr.register_worker("w1")
        mgr.heartbeat("w1")  # keep alive
        mgr.track_job("job_001", "w1", {"stale": True})
        time.sleep(0.1)
        requeued = mgr.check_health()
        assert any(j.get("stale") for j in requeued)

    def test_background_monitor_thread(self):
        from hashaxe.distributed.healing import WorkerHealthManager

        mgr = WorkerHealthManager()
        mgr.start()
        assert mgr._running
        mgr.stop()
        assert not mgr._running
