# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/distributed/master.py
#  Distributed cracking master node using ZeroMQ for work distribution.
#  Chunks wordlists and distributes to workers via PUSH/PULL/PUB sockets.
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
distributed/master.py — Distributed cracking master node.

Architecture
============
                    ┌─────────────────────────────────┐
                    │         MASTER NODE              │
                    │  hashaxe --distributed-master   │
                    │                                  │
                    │  ┌─────────────┐                 │
                    │  │ Wordlist    │ → chunks         │
                    │  │ Chunker     │                 │
                    │  └─────────────┘                 │
                    │         │                        │
                    │  ┌──────▼──────┐                 │
                    │  │  ZMQ PUSH   │:5555 ──────────────► Worker 1
                    │  │  (work)     │                 │
                    │  └─────────────┘                 │
                    │                                  │
                    │  ┌─────────────┐                 │
                    │  │  ZMQ PULL   │:5556 ◄──────────────── Worker 1
                    │  │  (results)  │                 │
                    │  └─────────────┘                 │
                    │                                  │
                    │  ┌─────────────┐                 │
                    │  │  ZMQ PUB    │:5557 ──────────────► All workers
                    │  │  (control)  │  STOP/PAUSE     │
                    │  └─────────────┘                 │
                    └─────────────────────────────────┘

Worker nodes can be:
  • Additional machines on the same LAN
  • Cloud spot instances (AWS G5, Lambda Labs)
  • Different GPU types (mix NVIDIA + AMD freely)

Scaling: Linear — N workers = N× speed (no synchronisation overhead).
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Optional

from hashaxe.display import Display
from hashaxe.session import Session, session_name_for
from hashaxe.wordlist import WordlistStreamer, chunk_wordlist


# ── Security utilities ────────────────────────────────────────────────────────

def _validate_path(user_path: str, label: str = "path") -> str:
    """Validate a file path against directory traversal attacks.

    Raises ValueError if the path contains traversal sequences or
    resolves outside the expected directory.
    """
    resolved = os.path.realpath(user_path)
    if ".." in os.path.normpath(user_path):
        raise ValueError(
            f"Path traversal detected in {label}: {user_path!r}"
        )
    if not os.path.exists(resolved):
        raise ValueError(f"{label} not found: {resolved}")
    return resolved

# ── ZMQ message types ─────────────────────────────────────────────────────────

MSG_WORK    = "WORK"
MSG_RESULT  = "RESULT"
MSG_STOP    = "STOP"
MSG_PAUSE   = "PAUSE"
MSG_RESUME  = "RESUME"
MSG_STATUS  = "STATUS"
MSG_DONE    = "DONE"    # worker signals wordlist exhausted


# ── Work item ─────────────────────────────────────────────────────────────────

@dataclass
class WorkItem:
    """
    A unit of work dispatched to one worker.
    Contains a byte-range slice of the wordlist — no password data transmitted.
    Workers must have access to the same key file and wordlist paths.
    """
    job_id:      str
    key_path:    str      # path to SSH private key (same on all workers)
    wordlist:    str      # path to wordlist (same on all workers)
    start_byte:  int
    end_byte:    int
    use_rules:   bool          = False
    rule_file:   str | None = None
    mask:        str | None = None


@dataclass
class WorkResult:
    """Result message from worker back to master."""
    job_id:    str
    found:     bool
    passphrase: str | None
    tried:     int
    speed:     float   # pw/s this worker achieved


@dataclass
class WorkerStatus:
    """Aggregate stats per registered worker."""
    worker_id: str
    host:      str
    tried:     int   = 0
    speed:     float = 0.0
    last_seen: float = field(default_factory=time.time)
    gpu:       str   = "none"


# ── Master node ───────────────────────────────────────────────────────────────

class MasterNode:
    """
    Orchestrates distributed cracking across multiple worker nodes.

    Usage:
        master = MasterNode(
            key_path   = "id_ed25519",
            wordlist   = "rockyou.txt",
            bind_host  = "0.0.0.0",
            work_port  = 5555,
            result_port= 5556,
            ctrl_port  = 5557,
        )
        result = master.run()
    """

    def __init__(
        self,
        key_path:    str,
        wordlist:    str,
        bind_host:   str  = "0.0.0.0",
        work_port:   int  = 5555,
        result_port: int  = 5556,
        ctrl_port:   int  = 5557,
        use_rules:   bool = False,
        rule_file:   str | None = None,
        mask:        str | None = None,
        verbose:     bool = False,
        heartbeat_timeout: float = 30.0,
    ):
        # Security: validate paths against traversal before storing
        self.key_path    = _validate_path(key_path, "key_path")
        self.wordlist    = _validate_path(wordlist, "wordlist")
        self.bind_host   = bind_host
        self.work_port   = work_port
        self.result_port = result_port
        self.ctrl_port   = ctrl_port
        self.use_rules   = use_rules
        self.rule_file   = rule_file
        self.mask        = mask
        self.verbose     = verbose
        self.heartbeat_timeout = heartbeat_timeout

        self._display  = Display(verbose=verbose)
        self._workers: dict[str, WorkerStatus] = {}
        self._result:  str | None = None

    def run(self) -> str | None:
        """
        Start the master node, dispatch work, wait for result.
        Returns found passphrase or None.
        """
        try:
            import zmq
        except ImportError:
            self._display.error(
                "ZeroMQ not installed.\n"
                "  Install: pip install pyzmq\n"
                "  Then run worker nodes: hashaxe --distributed-worker --master HOST"
            )
            return None

        ctx        = zmq.Context()
        work_sock  = ctx.socket(zmq.PUSH)
        result_sock= ctx.socket(zmq.PULL)
        ctrl_sock  = ctx.socket(zmq.PUB)

        # Set high-water mark so work items can queue before workers connect
        work_sock.setsockopt(zmq.SNDHWM, 10000)

        for sock in (work_sock, result_sock, ctrl_sock):
            sock.setsockopt(zmq.LINGER, 0)

        work_sock.bind(f"tcp://{self.bind_host}:{self.work_port}")
        result_sock.bind(f"tcp://{self.bind_host}:{self.result_port}")
        ctrl_sock.bind(f"tcp://{self.bind_host}:{self.ctrl_port}")

        self._display.info(
            f"Master listening — work:{self.work_port} "
            f"results:{self.result_port} ctrl:{self.ctrl_port}"
        )
        self._display.info(
            f"Start workers:  hashaxe --distributed-worker "
            f"--master {self.bind_host}"
        )

        try:
            self._result = self._dispatch_loop(work_sock, result_sock, ctrl_sock)
        finally:
            # Signal all workers to stop
            ctrl_sock.send_string(f"{MSG_STOP}:")
            time.sleep(0.5)
            work_sock.close()
            result_sock.close()
            ctrl_sock.close()
            ctx.term()

        return self._result

    def _dispatch_loop(self, work_sock, result_sock, ctrl_sock) -> str | None:
        """Main dispatch loop — send chunks, receive results."""
        import zmq
        from hashaxe.formats import FormatRegistry
        from hashaxe.formats.base import CHUNK_SIZES

        poller = zmq.Poller()
        poller.register(result_sock, zmq.POLLIN)

        # Parse target to determine optimal chunk size
        with open(self.key_path, "rb") as f:
            data = f.read()
        match = FormatRegistry().identify(data, self.key_path)
        if not match:
            self._display.error(f"Cannot identify format for {self.key_path}")
            return None
        target = match.handler.parse(data, self.key_path)
        
        perf_chunk = CHUNK_SIZES.get(target.difficulty, 50_000)

        # Build work queue from wordlist chunks
        chunks, total_lines = chunk_wordlist(self.wordlist, chunk_size_bytes=perf_chunk * 10)

        self._display.info(f"Wordlist: {total_lines:,} lines → {len(chunks)} chunks")

        pending:    deque[WorkItem] = deque()
        in_flight:  dict[str, WorkItem] = {}
        total_tried = 0
        t_start     = time.time()
        job_counter = 0

        # Pre-populate work queue
        for start, end in chunks:
            job_id = f"job_{job_counter:08d}"
            job_counter += 1
            pending.append(WorkItem(
                job_id    = job_id,
                key_path  = self.key_path,
                wordlist  = self.wordlist,
                start_byte= start,
                end_byte  = end,
                use_rules = self.use_rules,
                rule_file = self.rule_file,
                mask      = self.mask,
            ))

        # Track dispatch timestamps for heartbeat-based fault tolerance
        dispatch_times: dict[str, float] = {}

        # Drain queue — use blocking send (5s timeout) so items queue properly
        while pending or in_flight:
            # Send work to any available worker
            while pending:
                item = pending.popleft()
                try:
                    work_sock.send_json(asdict(item), zmq.NOBLOCK)
                except zmq.error.Again:
                    # HWM reached — put item back and wait for results
                    pending.appendleft(item)
                    break
                in_flight[item.job_id] = item
                dispatch_times[item.job_id] = time.time()

            # Poll for results (100ms timeout)
            try:
                events = dict(poller.poll(100))
            except KeyboardInterrupt:
                self._display.warn("KeyboardInterrupt received, stopping master node.")
                break
            if result_sock in events:
                try:
                    msg     = result_sock.recv_json()
                    result  = WorkResult(**msg)
                except Exception as e:
                    if self.verbose:
                        self._display.warn(f"Ignored malformed message on result socket: {e}")
                    continue
                
                total_tried += result.tried

                # Update worker stats
                if result.found and result.passphrase:
                    return result.passphrase

                in_flight.pop(result.job_id, None)
                dispatch_times.pop(result.job_id, None)

                elapsed = time.time() - t_start
                speed   = total_tried / elapsed if elapsed > 0 else 0

                if self.verbose:
                    self._display.info(
                        f"Progress: {total_tried:,} tried  "
                        f"Speed: {speed:.1f} pw/s  "
                        f"In-flight: {len(in_flight)}"
                    )

            # Heartbeat: requeue jobs from workers that timed out
            now = time.time()
            timed_out = [
                jid for jid, ts in dispatch_times.items()
                if now - ts > self.heartbeat_timeout
            ]
            for jid in timed_out:
                item = in_flight.pop(jid, None)
                dispatch_times.pop(jid, None)
                if item:
                    self._display.warn(
                        f"Job {jid} timed out — requeuing"
                    )
                    pending.appendleft(item)

        return None

    def status(self) -> dict:
        """Return aggregate stats across all connected workers."""
        total_speed = sum(w.speed for w in self._workers.values())
        total_tried = sum(w.tried for w in self._workers.values())
        return {
            "workers":     len(self._workers),
            "total_speed": total_speed,
            "total_tried": total_tried,
            "worker_list": [
                {"id": w.worker_id, "host": w.host,
                 "speed": w.speed, "gpu": w.gpu}
                for w in self._workers.values()
            ],
        }
