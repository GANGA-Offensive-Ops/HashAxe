# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/distributed/worker.py
#  Distributed cracking worker node for connecting to master and processing chunks.
#  Uses local CPU threads + GPU for cracking, reports results back to master.
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
distributed/worker.py — Distributed cracking worker node.

Each worker connects to a master, receives work items (byte-range chunks),
cracks locally using all available resources (CPU threads + GPU if present),
and reports results back.

Multiple workers can run on the same machine (rare) or across a cluster.
GPU workers are first-class: if a worker has a GPU, it uses gpu/accelerator.py
automatically and reports its estimated GPU speed to the master.

Usage:
    # Same machine
    hashaxe --distributed-worker --master 127.0.0.1

    # Remote machine (key + wordlist must be accessible at same path)
    hashaxe --distributed-worker --master 192.168.1.10 --threads 8

    # With GPU
    hashaxe --distributed-worker --master 192.168.1.10 --gpu

    # AWS G5 one-liner
    pip install hashaxe pyzmq pycuda && \\
    hashaxe --distributed-worker --master $MASTER_IP
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from hashaxe.distributed.master import MSG_PAUSE, MSG_RESUME, MSG_STOP, WorkItem, WorkResult


class WorkerNode:
    """
    Connects to a MasterNode and processes work items.

    Each work item is a (wordlist_path, start_byte, end_byte) range.
    The worker opens the file, seeks to start_byte, and cracks locally.
    """

    def __init__(
        self,
        master_host: str,
        work_port: int = 5555,
        result_port: int = 5556,
        ctrl_port: int = 5557,
        threads: int = 0,
        use_gpu: bool = True,
        verbose: bool = False,
    ):
        self.master_host = master_host
        self.work_port = work_port
        self.result_port = result_port
        self.ctrl_port = ctrl_port
        self.threads = threads or os.cpu_count() or 2
        self.use_gpu = use_gpu
        self.verbose = verbose
        self.worker_id = f"worker_{uuid.uuid4().hex[:8]}"
        self.hostname = socket.gethostname()

        # GPU detection
        self._gpu_device = None
        if use_gpu:
            try:
                from hashaxe.gpu.accelerator import detect_gpu

                self._gpu_device = detect_gpu()
            except Exception:
                pass

    def run(self) -> None:
        """Connect to master and process work items until STOP received."""
        try:
            import zmq
        except ImportError:
            print("[!] pyzmq required: pip install pyzmq")
            return

        ctx = zmq.Context()
        work_sock = ctx.socket(zmq.PULL)
        result_sock = ctx.socket(zmq.PUSH)
        ctrl_sock = ctx.socket(zmq.SUB)

        work_sock.connect(f"tcp://{self.master_host}:{self.work_port}")
        result_sock.connect(f"tcp://{self.master_host}:{self.result_port}")
        ctrl_sock.connect(f"tcp://{self.master_host}:{self.ctrl_port}")
        ctrl_sock.setsockopt_string(zmq.SUBSCRIBE, "")

        print(
            f"[*] Worker {self.worker_id} connected to {self.master_host}\n"
            f"    Threads: {self.threads}  "
            f"GPU: {self._gpu_device.name if self._gpu_device else 'none'}"
        )

        poller = zmq.Poller()
        poller.register(work_sock, zmq.POLLIN)
        poller.register(ctrl_sock, zmq.POLLIN)

        paused = False

        try:
            while True:
                events = dict(poller.poll(500))

                # Control messages
                if ctrl_sock in events:
                    msg = ctrl_sock.recv_string()
                    if msg.startswith(MSG_STOP):
                        print(f"[*] Worker {self.worker_id}: STOP received, exiting.")
                        break
                    elif msg.startswith(MSG_PAUSE):
                        paused = True
                        print(f"[*] Worker {self.worker_id}: paused.")
                    elif msg.startswith(MSG_RESUME):
                        paused = False
                        print(f"[*] Worker {self.worker_id}: resumed.")

                if paused:
                    time.sleep(0.1)
                    continue

                # Work items
                if work_sock in events:
                    raw = work_sock.recv_json()
                    item = WorkItem(**raw)
                    result = self._process(item)
                    result_sock.send_json(
                        {
                            "job_id": result.job_id,
                            "found": result.found,
                            "passphrase": result.passphrase,
                            "tried": result.tried,
                            "speed": result.speed,
                        }
                    )
                    if result.found:
                        break

        finally:
            work_sock.close()
            result_sock.close()
            ctrl_sock.close()
            ctx.term()

    def _process(self, item: WorkItem) -> WorkResult:
        """
        Process one work item: hashaxe the byte-range chunk of the wordlist.
        Routes to GPU or CPU path based on what's available.
        """
        import multiprocessing

        from hashaxe.formats import FormatRegistry
        from hashaxe.rules.hashcat import apply_rules_from_file, load_rule_file
        from hashaxe.rules.mask import MaskEngine
        from hashaxe.rules.mutations import apply_rules
        from hashaxe.wordlist import WordlistStreamer

        # Workers must have the key file at the same path as the master.
        # This is standard for LAN setups. For cloud workers, deploy_aws.py
        # uploads the key via EC2 user-data to /tmp/target.key.
        registry = FormatRegistry()
        from pathlib import Path

        data = Path(item.key_path).read_bytes()
        match = registry.identify(data, Path(item.key_path))
        if not match:
            return WorkResult(job_id=item.job_id, found=False, passphrase=None, tried=0, speed=0.0)
        target = match.handler.parse(data, Path(item.key_path))
        handler = match.handler

        streamer = WordlistStreamer(item.wordlist)
        t_start = time.time()
        tried = 0

        compiled_rules = None
        if item.rule_file:
            try:
                compiled_rules = load_rule_file(item.rule_file)
            except Exception as e:
                print(
                    f"[!] Worker {self.worker_id}: Failed to load rule file {item.rule_file}: {e}"
                )

        # ARCH-3: Pre-build MaskEngine once per work item, not per line
        mask_engine = MaskEngine(item.mask) if item.mask else None

        for raw_line in streamer.lines(item.start_byte, item.end_byte):
            word = raw_line.rstrip(b"\r\n").decode("utf-8", errors="replace")
            if not word:
                continue

            if compiled_rules:
                candidates = list(apply_rules_from_file(word, compiled_rules))
                candidates.insert(0, word)
            elif item.use_rules:
                candidates = list(apply_rules(word))
            elif mask_engine:
                candidates = [word + s for s in mask_engine.candidates()]
            else:
                candidates = [word]

            for candidate in candidates:
                tried += 1
                pw = candidate.encode("utf-8", "replace")
                if handler.verify(target, pw):
                    if handler.verify_full(target, pw):
                        elapsed = time.time() - t_start
                        speed = tried / elapsed if elapsed > 0 else 0
                        return WorkResult(
                            job_id=item.job_id,
                            found=True,
                            passphrase=candidate,
                            tried=tried,
                            speed=speed,
                        )

        elapsed = time.time() - t_start
        speed = tried / elapsed if elapsed > 0 else 0
        return WorkResult(
            job_id=item.job_id,
            found=False,
            passphrase=None,
            tried=tried,
            speed=speed,
        )
