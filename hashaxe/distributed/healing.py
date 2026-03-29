# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/distributed/healing.py
#  Distributed fault-tolerance and auto-recovery for worker node failures.
#  Monitors heartbeats, re-queues work from dead workers, manages cluster health.
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
hashaxe.distributed.healing — Distributed fault-tolerance and auto-recovery.

Provides automatic detection and recovery of failed/stalled worker nodes
in the distributed cracking architecture. Ensures no work items are lost
when workers crash, disconnect, or experience hardware failures.

Features:
  - Worker heartbeat monitoring (configurable timeout)
  - Automatic work item re-queuing on worker failure
  - Graceful degradation support (continue with remaining workers)
  - Worker health scoring and load balancing
  - Dead worker cleanup and resource reclamation
  - Stale job detection and re-dispatch

Architecture:
  WorkerHealthManager runs alongside MasterNode and:
    1. Tracks heartbeats from all registered workers
    2. Detects workers that miss heartbeat deadlines
    3. Re-queues assigned work items from dead workers
    4. Reports cluster health to the display layer
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Default timeouts
_HEARTBEAT_INTERVAL = 5.0  # workers send heartbeat every N seconds
_HEARTBEAT_TIMEOUT = 15.0  # consider worker dead after N seconds silence
_STALE_JOB_TIMEOUT = 60.0  # re-queue job if no result after N seconds
_CLEANUP_INTERVAL = 10.0  # run cleanup cycle every N seconds


@dataclass
class WorkerHealth:
    """Health tracking data for a single worker."""

    worker_id: str
    host: str = "unknown"
    gpu: str = ""
    first_seen: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    total_jobs_completed: int = 0
    total_jobs_failed: int = 0
    total_tried: int = 0
    avg_speed: float = 0.0
    is_alive: bool = True
    consecutive_failures: int = 0
    health_score: float = 1.0  # 0.0 = dead, 1.0 = perfect

    def update_heartbeat(self) -> None:
        """Record a heartbeat from this worker."""
        self.last_heartbeat = time.time()
        self.is_alive = True
        self.consecutive_failures = 0
        self._recalculate_score()

    def record_completion(self, tried: int, speed: float) -> None:
        """Record successful job completion."""
        self.total_jobs_completed += 1
        self.total_tried += tried
        self.avg_speed = (
            self.avg_speed * (self.total_jobs_completed - 1) + speed
        ) / self.total_jobs_completed
        self._recalculate_score()

    def record_failure(self) -> None:
        """Record a job failure from this worker."""
        self.total_jobs_failed += 1
        self.consecutive_failures += 1
        self._recalculate_score()

    def _recalculate_score(self) -> None:
        """Calculate health score (0.0 to 1.0)."""
        total = self.total_jobs_completed + self.total_jobs_failed
        if total == 0:
            self.health_score = 1.0
            return

        success_rate = self.total_jobs_completed / total
        failure_penalty = min(1.0, self.consecutive_failures * 0.25)
        self.health_score = max(0.0, success_rate - failure_penalty)

    @property
    def seconds_since_heartbeat(self) -> float:
        return time.time() - self.last_heartbeat

    @property
    def uptime(self) -> float:
        return time.time() - self.first_seen


@dataclass
class InFlightJob:
    """Tracking data for a work item currently being processed."""

    job_id: str
    worker_id: str
    dispatched_at: float = field(default_factory=time.time)
    work_data: dict = field(default_factory=dict)

    @property
    def age(self) -> float:
        return time.time() - self.dispatched_at


class WorkerHealthManager:
    """Monitors worker health and implements auto-healing.

    Thread-safe — designed to run concurrently with the master dispatch loop.

    Usage:
        manager = WorkerHealthManager(
            on_worker_dead=requeue_callback,
            heartbeat_timeout=15.0,
        )
        manager.start()
        manager.register_worker("w1", host="192.168.1.10", gpu="RTX 3050")
        manager.heartbeat("w1")
        manager.track_job("job_001", "w1", work_data={...})
        # ... later:
        dead_jobs = manager.check_health()  # returns re-queued job data
        manager.stop()
    """

    def __init__(
        self,
        heartbeat_timeout: float = _HEARTBEAT_TIMEOUT,
        stale_job_timeout: float = _STALE_JOB_TIMEOUT,
        on_worker_dead: Callable[[str, list[dict]], None] | None = None,
    ):
        self._timeout = heartbeat_timeout
        self._stale_timeout = stale_job_timeout
        self._on_dead = on_worker_dead  # callback(worker_id, [requeued_jobs])

        self._lock = threading.Lock()
        self._workers: dict[str, WorkerHealth] = {}
        self._in_flight: dict[str, InFlightJob] = {}
        self._running = False
        self._monitor_thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the health monitoring background thread."""
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="worker-health-monitor",
        )
        self._monitor_thread.start()
        logger.info("Worker health monitor started (timeout=%.1fs)", self._timeout)

    def stop(self) -> None:
        """Stop the health monitoring thread."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        logger.info("Worker health monitor stopped")

    def register_worker(self, worker_id: str, host: str = "unknown", gpu: str = "") -> None:
        """Register a new worker node."""
        with self._lock:
            if worker_id not in self._workers:
                self._workers[worker_id] = WorkerHealth(
                    worker_id=worker_id,
                    host=host,
                    gpu=gpu,
                )
                logger.info(
                    "Worker registered: %s (%s, GPU: %s)",
                    worker_id,
                    host,
                    gpu or "none",
                )

    def heartbeat(self, worker_id: str) -> None:
        """Process a heartbeat from a worker."""
        with self._lock:
            if worker_id in self._workers:
                self._workers[worker_id].update_heartbeat()

    def track_job(self, job_id: str, worker_id: str, work_data: dict | None = None) -> None:
        """Track a dispatched job for timeout monitoring."""
        with self._lock:
            self._in_flight[job_id] = InFlightJob(
                job_id=job_id,
                worker_id=worker_id,
                work_data=work_data or {},
            )

    def complete_job(self, job_id: str, tried: int = 0, speed: float = 0.0) -> None:
        """Mark a job as completed successfully."""
        with self._lock:
            job = self._in_flight.pop(job_id, None)
            if job and job.worker_id in self._workers:
                self._workers[job.worker_id].record_completion(tried, speed)

    def fail_job(self, job_id: str) -> dict | None:
        """Mark a job as failed and return its data for re-queuing."""
        with self._lock:
            job = self._in_flight.pop(job_id, None)
            if job:
                if job.worker_id in self._workers:
                    self._workers[job.worker_id].record_failure()
                return job.work_data
        return None

    def check_health(self) -> list[dict]:
        """Check all workers and return re-queued work data from dead workers.

        This is the core healing method. Call periodically or let the
        background thread handle it automatically.
        """
        requeued: list[dict] = []
        now = time.time()

        with self._lock:
            dead_workers: list[str] = []

            # Detect dead workers
            for wid, w in self._workers.items():
                if w.is_alive and (now - w.last_heartbeat) > self._timeout:
                    w.is_alive = False
                    w.health_score = 0.0
                    dead_workers.append(wid)
                    logger.warning(
                        "Worker %s (%s) declared DEAD (no heartbeat for %.1fs)",
                        wid,
                        w.host,
                        now - w.last_heartbeat,
                    )

            # Re-queue jobs from dead workers
            jobs_to_requeue: list[str] = []
            for jid, job in self._in_flight.items():
                if job.worker_id in dead_workers:
                    jobs_to_requeue.append(jid)
                elif job.age > self._stale_timeout:
                    jobs_to_requeue.append(jid)
                    logger.warning(
                        "Job %s stale (%.1fs old), re-queuing",
                        jid,
                        job.age,
                    )

            for jid in jobs_to_requeue:
                job = self._in_flight.pop(jid, None)
                if job and job.work_data:
                    requeued.append(job.work_data)

        # Fire callback if provided
        if requeued and self._on_dead:
            for wid in dead_workers:
                self._on_dead(wid, requeued)

        return requeued

    def cluster_status(self) -> dict[str, Any]:
        """Get cluster health summary."""
        with self._lock:
            now = time.time()
            alive = [w for w in self._workers.values() if w.is_alive]
            dead = [w for w in self._workers.values() if not w.is_alive]

            return {
                "total_workers": len(self._workers),
                "alive": len(alive),
                "dead": len(dead),
                "in_flight_jobs": len(self._in_flight),
                "avg_health_score": (
                    sum(w.health_score for w in self._workers.values()) / len(self._workers)
                    if self._workers
                    else 0
                ),
                "total_speed": sum(w.avg_speed for w in alive),
                "total_tried": sum(w.total_tried for w in self._workers.values()),
                "workers": [
                    {
                        "id": w.worker_id,
                        "host": w.host,
                        "alive": w.is_alive,
                        "health": round(w.health_score, 2),
                        "speed": round(w.avg_speed, 1),
                        "jobs_done": w.total_jobs_completed,
                        "jobs_failed": w.total_jobs_failed,
                        "uptime_sec": round(w.uptime, 1),
                        "last_hb_ago": round(now - w.last_heartbeat, 1),
                    }
                    for w in self._workers.values()
                ],
            }

    def best_workers(self, n: int = 5) -> list[str]:
        """Return IDs of the top N healthiest workers for load balancing."""
        with self._lock:
            alive = [w for w in self._workers.values() if w.is_alive]
            ranked = sorted(alive, key=lambda w: w.health_score, reverse=True)
            return [w.worker_id for w in ranked[:n]]

    def _monitor_loop(self) -> None:
        """Background thread: periodically check health."""
        while self._running:
            try:
                requeued = self.check_health()
                if requeued:
                    logger.info(
                        "Auto-healed: %d jobs re-queued from dead workers",
                        len(requeued),
                    )
            except Exception as e:
                logger.error("Health monitor error: %s", e)
            time.sleep(_CLEANUP_INTERVAL)
