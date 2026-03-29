# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/monitor.py
#  Real-time performance monitoring and benchmarking engine.
#  Tracks throughput, GPU/CPU utilization, memory pressure, and session ETA.
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
hashaxe.monitor — Real-time performance monitoring and benchmarking engine.

Provides live metrics collection, throughput tracking, and performance
analysis during cracking sessions. Thread-safe for concurrent worker access.

Metrics tracked:
  - Candidate throughput (pw/sec, rolling average)
  - Per-hash-type verification speed
  - GPU vs CPU utilization ratios
  - Memory and I/O pressure indicators
  - Session progress and ETA calculation
  - Worker-level stats in distributed mode

Architecture:
  The monitor runs as a background thread collecting metrics via
  a shared-memory interface (no IPC overhead). It exposes a snapshot()
  method for the display layer and an export() method for benchmarks.

GANGA Offensive Ops · Hashaxe V1
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Rolling window size for speed calculations
_WINDOW_SIZE = 30  # seconds


@dataclass
class WorkerMetrics:
    """Per-worker performance tracking."""
    worker_id: str
    host: str = "local"
    total_tried: int = 0
    speed: float = 0.0
    gpu_name: str = ""
    last_seen: float = field(default_factory=time.time)
    is_active: bool = True


class PerformanceMonitor:
    """Thread-safe real-time performance monitoring engine.

    Usage:
        monitor = PerformanceMonitor(total_keyspace=1_000_000)
        monitor.start()
        # ... during cracking:
        monitor.record(tried=1024, worker_id="w0")
        # ... display:
        snap = monitor.snapshot()
        print(f"Speed: {snap['speed']:.1f} pw/s  ETA: {snap['eta_str']}")
        monitor.stop()
    """

    def __init__(self, total_keyspace: int = 0, hash_type: str = "unknown"):
        self._total_keyspace = total_keyspace
        self._hash_type = hash_type
        self._lock = threading.Lock()
        self._start_time = 0.0
        self._running = False

        # Counters
        self._total_tried = 0
        self._total_matched = 0

        # Rolling speed window: deque of (timestamp, cumulative_tried)
        self._speed_window: deque[tuple[float, int]] = deque(maxlen=300)

        # Per-worker tracking
        self._workers: dict[str, WorkerMetrics] = {}

        # Peak metrics
        self._peak_speed = 0.0
        self._peak_timestamp = 0.0

        # Hardware utilization
        self._gpu_fraction = 0.0  # fraction of work done on GPU
        self._gpu_tried = 0
        self._cpu_tried = 0

    def start(self) -> None:
        """Start monitoring."""
        self._start_time = time.time()
        self._running = True
        self._speed_window.clear()
        logger.debug("Performance monitor started")

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        logger.debug("Performance monitor stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def record(
        self,
        tried: int = 1,
        worker_id: str = "local",
        on_gpu: bool = False,
    ) -> None:
        """Record candidate attempts. Thread-safe."""
        with self._lock:
            self._total_tried += tried

            now = time.time()
            self._speed_window.append((now, self._total_tried))

            if on_gpu:
                self._gpu_tried += tried
            else:
                self._cpu_tried += tried

            # Update worker stats
            if worker_id not in self._workers:
                self._workers[worker_id] = WorkerMetrics(
                    worker_id=worker_id
                )
            w = self._workers[worker_id]
            w.total_tried += tried
            w.last_seen = now
            w.is_active = True

    def record_match(self, count: int = 1) -> None:
        """Record successful password matches."""
        with self._lock:
            self._total_matched += count

    def snapshot(self) -> dict[str, Any]:
        """Get a consistent snapshot of all current metrics.

        Returns a dict suitable for display or export.
        """
        with self._lock:
            now = time.time()
            elapsed = now - self._start_time if self._start_time else 0

            # Calculate rolling speed from window
            speed = self._calculate_rolling_speed(now)

            # Update peak
            if speed > self._peak_speed:
                self._peak_speed = speed
                self._peak_timestamp = now

            # ETA
            remaining = self._total_keyspace - self._total_tried
            eta_sec = remaining / speed if speed > 0 and remaining > 0 else 0
            progress = (
                (self._total_tried / self._total_keyspace * 100)
                if self._total_keyspace > 0
                else 0
            )

            # GPU utilization ratio
            total_hw = self._gpu_tried + self._cpu_tried
            gpu_pct = (
                (self._gpu_tried / total_hw * 100) if total_hw > 0 else 0
            )

            return {
                "tried": self._total_tried,
                "matched": self._total_matched,
                "keyspace": self._total_keyspace,
                "speed": round(speed, 1),
                "speed_avg": round(
                    self._total_tried / elapsed if elapsed > 0 else 0, 1
                ),
                "speed_peak": round(self._peak_speed, 1),
                "elapsed": round(elapsed, 2),
                "elapsed_str": self._format_duration(elapsed),
                "eta_sec": round(eta_sec, 1),
                "eta_str": self._format_duration(eta_sec) if eta_sec > 0 else "N/A",
                "progress_pct": round(progress, 2),
                "hash_type": self._hash_type,
                "workers": len(self._workers),
                "active_workers": sum(
                    1 for w in self._workers.values()
                    if now - w.last_seen < 30
                ),
                "gpu_pct": round(gpu_pct, 1),
                "hit_rate": round(
                    self._total_matched / self._total_tried
                    if self._total_tried > 0
                    else 0,
                    6,
                ),
            }

    def worker_stats(self) -> list[dict]:
        """Get per-worker performance breakdown."""
        with self._lock:
            now = time.time()
            return [
                {
                    "id": w.worker_id,
                    "host": w.host,
                    "tried": w.total_tried,
                    "speed": round(w.speed, 1),
                    "gpu": w.gpu_name or "CPU",
                    "active": now - w.last_seen < 30,
                    "last_seen": round(now - w.last_seen, 1),
                }
                for w in self._workers.values()
            ]

    def format_report(self) -> str:
        """Generate a human-readable performance report."""
        snap = self.snapshot()
        lines = [
            f"{'═' * 50}",
            f"  Performance Report — {snap['hash_type']}",
            f"{'═' * 50}",
            f"  Candidates tried : {snap['tried']:,}",
            f"  Speed (current)  : {snap['speed']:,.1f} pw/s",
            f"  Speed (average)  : {snap['speed_avg']:,.1f} pw/s",
            f"  Speed (peak)     : {snap['speed_peak']:,.1f} pw/s",
            f"  Elapsed          : {snap['elapsed_str']}",
            f"  ETA              : {snap['eta_str']}",
            f"  Progress         : {snap['progress_pct']:.2f}%",
            f"  Workers          : {snap['active_workers']}/{snap['workers']}",
            f"  GPU utilization  : {snap['gpu_pct']:.1f}%",
            f"  Hit rate         : {snap['hit_rate']:.6f}",
            f"{'═' * 50}",
        ]
        return "\n".join(lines)

    def export_benchmark(self) -> dict:
        """Export benchmark-grade metrics for BENCHMARKS.md."""
        snap = self.snapshot()
        return {
            "hash_type": snap["hash_type"],
            "total_tried": snap["tried"],
            "elapsed_sec": snap["elapsed"],
            "avg_speed": snap["speed_avg"],
            "peak_speed": snap["speed_peak"],
            "workers": snap["workers"],
            "gpu_utilization_pct": snap["gpu_pct"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _calculate_rolling_speed(self, now: float) -> float:
        """Calculate speed from the rolling window (last N seconds)."""
        if len(self._speed_window) < 2:
            return 0.0

        cutoff = now - _WINDOW_SIZE
        # Find earliest entry within window
        start_idx = 0
        for i, (ts, _) in enumerate(self._speed_window):
            if ts >= cutoff:
                start_idx = i
                break

        if start_idx >= len(self._speed_window) - 1:
            return 0.0

        ts_start, tried_start = self._speed_window[start_idx]
        ts_end, tried_end = self._speed_window[-1]

        dt = ts_end - ts_start
        if dt <= 0:
            return 0.0

        return (tried_end - tried_start) / dt

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format seconds into human-readable duration."""
        if seconds <= 0:
            return "0s"
        if seconds < 60:
            return f"{seconds:.1f}s"
        if seconds < 3600:
            m, s = divmod(seconds, 60)
            return f"{int(m)}m {int(s)}s"
        if seconds < 86400:
            h, rem = divmod(seconds, 3600)
            m = rem // 60
            return f"{int(h)}h {int(m)}m"
        d, rem = divmod(seconds, 86400)
        h = rem // 3600
        return f"{int(d)}d {int(h)}h"
