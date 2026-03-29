# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/cracker.py
#  Main cracking orchestrator with GPU acceleration, CPU SIMD batching, and distributed mode.
#  Coordinates wordlist ordering, worker speed reporting, and session management.
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
cracker.py — Main cracking orchestrator (v2 — Batch 2 update).

New in Batch 2:
  • GPU acceleration via gpu/accelerator.py (auto-detected)
  • CPU SIMD batching via cpu/simd.py (numpy vectorised)
  • Smart wordlist ordering via cpu/wordfreq.py
  • Distributed mode (--distributed-master / --distributed-worker)
  • Per-worker speed reporting in verbose mode
  • GPU info line in banner
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from hashaxe.attacks import AttackConfig, AttackRegistry
from hashaxe.display import Display
from hashaxe.formats import FormatRegistry, FormatTarget
from hashaxe.rules.hashcat import apply_rules_from_file, load_rule_file
from hashaxe.rules.mask import MaskEngine
from hashaxe.rules.mutations import apply_rules, count_rules
from hashaxe.session import Session, session_name_for
from hashaxe.wordlist import WordlistStreamer, chunk_wordlist, validate_wordlist

# Module-level globals for sharing across pool workers.
# Set by _init_worker() when the Pool is created.
_found_event = None
_shared_counter = None


def _init_worker(event, counter):
    """Pool initializer: stores shared Event + counter in module globals."""
    import signal

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    global _found_event, _shared_counter
    _found_event = event
    _shared_counter = counter


def _worker(args: tuple) -> tuple[str | None, int]:
    (
        target,
        wordlist_path,
        start_byte,
        end_byte,
        use_rules,
        rule_data,
        mask_str,
        custom_charsets,
        use_smart_order,
    ) = args

    tried = 0
    local_count = 0  # Batched counter to avoid lock contention
    update_mask = {1: 0x3FFF, 2: 0x7FF, 3: 0x0, 4: 0x0, 5: 0x0}.get(target.difficulty.value, 0x3F)
    streamer = WordlistStreamer(wordlist_path)
    handler = FormatRegistry().get(target.format_id)
    if not handler:
        return (None, 0)

    # Pre-build MaskEngine outside the loop (ARCH-2 fix)
    mask_engine = MaskEngine(mask_str, custom_charsets) if mask_str else None

    for raw_line in streamer.lines(start_byte, end_byte):
        # Batch the found_event check (PERF-2: every 1024 iterations)
        if tried & update_mask == 0 and _found_event.is_set():
            break
        word = raw_line.rstrip(b"\r\n").decode("utf-8", errors="replace")
        if not word:
            continue

        if rule_data:
            candidates = list(apply_rules_from_file(word, rule_data))
            candidates.insert(0, word)
        elif use_rules:
            candidates = list(apply_rules(word))
        elif mask_engine:
            candidates = [word + s for s in mask_engine.candidates()]
        else:
            candidates = [word]

        # Sorting 500+ generated candidates per word using regexes crushes CPU
        # performance (yielding 2.4 H/s). Only apply smart_sort for small candidate expansions.
        if use_smart_order and 1 < len(candidates) <= 20:
            try:
                from hashaxe.cpu.wordfreq import smart_sort

                candidates = smart_sort(candidates)
            except ImportError:
                pass

        for candidate in candidates:
            if tried & update_mask == 0 and _found_event.is_set():
                break
            tried += 1
            local_count += 1
            # Flush counter every 1024 iterations (atomic batch update)
            if local_count & update_mask == 0:
                with _shared_counter.get_lock():
                    _shared_counter.value += local_count
                local_count = 0
            pw_bytes = candidate.encode("utf-8", "replace")
            if handler.verify(target, pw_bytes):
                if handler.verify_full(target, pw_bytes):
                    _found_event.set()
                    with _shared_counter.get_lock():
                        _shared_counter.value += local_count
                    return (candidate, tried)

    # Final flush of remaining count
    if local_count > 0:
        with _shared_counter.get_lock():
            _shared_counter.value += local_count
    return (None, tried)


def _mask_worker(args: tuple) -> tuple[str | None, int]:
    (target, mask_str, custom_charsets, skip, count) = args
    engine = MaskEngine(mask_str, custom_charsets)
    handler = FormatRegistry().get(target.format_id)
    tried = 0
    local_count = 0
    update_mask = {1: 0x3FFF, 2: 0x7FF, 3: 0x0, 4: 0x0, 5: 0x0}.get(target.difficulty.value, 0x3F)
    if not handler:
        return (None, 0)
    for i, candidate in enumerate(engine.candidates_from(skip)):
        # Batch the found_event check (PERF-2: every 1024 iterations)
        if tried & update_mask == 0 and _found_event.is_set():
            break
        if i >= count:
            break
        tried += 1
        local_count += 1
        if local_count & update_mask == 0:
            with _shared_counter.get_lock():
                _shared_counter.value += local_count
            local_count = 0
        pw_bytes = candidate.encode("utf-8", "replace")
        if handler.verify(target, pw_bytes):
            if handler.verify_full(target, pw_bytes):
                _found_event.set()
                with _shared_counter.get_lock():
                    _shared_counter.value += local_count
                return (candidate, tried)
    if local_count > 0:
        with _shared_counter.get_lock():
            _shared_counter.value += local_count
    return (None, tried)


def _plugin_worker(args: tuple) -> tuple[str | None, int]:
    """Generic worker for advanced AttackRegistry generator plugins."""
    (target, attack_mode, config_dict, worker_id, num_workers) = args
    from hashaxe.attacks import AttackConfig, AttackRegistry

    atk_plugin = AttackRegistry().get(attack_mode)
    if not atk_plugin:
        return (None, 0)
    config = AttackConfig(**config_dict)
    handler = FormatRegistry().get(target.format_id)
    if not handler:
        return (None, 0)

    tried = 0
    local_count = 0
    update_mask = {1: 0x3FFF, 2: 0x7FF, 3: 0x0, 4: 0x0, 5: 0x0}.get(target.difficulty.value, 0x3F)
    # Generative models are slow to yield strings (ML inference / scraping).
    # We must flush to the shared progress counter on every attempt.
    if attack_mode in ("ai", "osint", "pcfg"):
        update_mask = 0x0
    import itertools

    gen = atk_plugin.generate(config)
    # Partition generation using islice so workers share the load round-robin
    for candidate in itertools.islice(gen, worker_id, None, num_workers):
        if tried & update_mask == 0 and _found_event.is_set():
            break
        tried += 1
        local_count += 1
        if local_count & update_mask == 0:
            with _shared_counter.get_lock():
                _shared_counter.value += local_count
            local_count = 0
        pw_bytes = candidate.encode("utf-8", "replace")
        if handler.verify(target, pw_bytes):
            if handler.verify_full(target, pw_bytes):
                _found_event.set()
                with _shared_counter.get_lock():
                    _shared_counter.value += local_count
                return (candidate, tried)
    if local_count > 0:
        with _shared_counter.get_lock():
            _shared_counter.value += local_count
    return (None, tried)


def _progress_poller(counter, found_event, display, total, t_start, n_workers, poll_interval=0.3):
    """Background thread: polls shared counter and updates the display live."""
    while not found_event.is_set():
        tried = counter.value
        elapsed = time.time() - t_start
        speed = tried / elapsed if elapsed > 0 else 0
        display.progress(tried, total, speed, n_workers)
        time.sleep(poll_interval)
        # Check if all workers are done (counter stopped changing)
        if tried >= total:
            break


from hashaxe.formats import BaseFormat


def benchmark(target: FormatTarget, handler: BaseFormat, display: Display, n_workers: int) -> float:
    display.info("Running benchmark (5 seconds)...")
    try:
        from hashaxe.gpu.accelerator import detect_gpu, gpu_info_string

        device = detect_gpu()
        if device and not display.quiet:
            display.ok(f"GPU: {gpu_info_string(device)}")
    except (ImportError, RuntimeError):
        pass

    test_passwords = [f"benchmark_test_{i}".encode() for i in range(200)]
    t_start = time.perf_counter()
    tested = 0
    for pw in test_passwords * 10:
        handler.verify(target, pw)
        tested += 1
        if time.perf_counter() - t_start >= 5.0:
            break

    elapsed = time.perf_counter() - t_start
    speed_per_core = tested / elapsed if elapsed > 0 else 0
    display.benchmark_result(
        key_path="",
        rounds=int(target.format_data.get("rounds", 1)),
        speed_per_core=speed_per_core,
        workers=n_workers,
    )
    return speed_per_core


def hashaxe(
    key_path: str | None = None,
    raw_hash: str | None = None,
    wordlist: str = "",
    threads: int = 0,
    use_rules: bool = False,
    rule_file: str | None = None,
    mask: str | None = None,
    custom_charsets: dict | None = None,
    verbose: bool = False,
    quiet: bool = False,
    output: str | None = None,
    session_name: str | None = None,
    restore: bool = False,
    do_benchmark: bool = False,
    use_gpu: bool = True,
    use_smart_order: bool = True,
    distributed_master: bool = False,
    distributed_worker: bool = False,
    master_host: str | None = None,
    verify_host: str | None = None,
    verify_port: int = 22,
    verify_user: str | None = None,
    attack_mode_override: str | None = None,
    wordlist2: str | None = None,
    policy: str | None = None,
    markov_order: int = 3,
    prince_min: int = 1,
    prince_max: int = 4,
    use_tui: bool = False,
    ai_candidates: int = 1000,
    format_override: str | None = None,
) -> str | None:
    display = Display(verbose=verbose, quiet=quiet)
    display.banner()

    if distributed_worker:
        if not master_host:
            display.error("--distributed-worker requires --master HOST")
            sys.exit(1)
        from hashaxe.distributed.worker import WorkerNode

        WorkerNode(master_host=master_host, threads=threads, use_gpu=use_gpu, verbose=verbose).run()
        return None

    if raw_hash:
        display.info(f"Loading raw hash: {raw_hash[:16]}...")
        data = raw_hash.encode("utf-8")
        src_path = None
    elif key_path:
        display.info(f"Loading target: {key_path}")
        try:
            data = Path(key_path).read_bytes()
        except FileNotFoundError:
            display.error(f"Target file not found: {key_path}")
            sys.exit(1)
        src_path = Path(key_path)
    else:
        display.error("No target provided (missing --key or --hash)")
        sys.exit(1)

    alt_candidates = []  # Alternative format matches for fallback
    try:
        registry = FormatRegistry()
        if format_override:
            handler = registry.get(format_override)
            if handler is None:
                display.error(f"Unknown format ID: {format_override}")
                display.info(f"Available: {', '.join(registry.list_ids())}")
                sys.exit(1)
            target = handler.parse(data, src_path)
        else:
            all_matches = registry.identify_all(data, src_path)
            if not all_matches:
                display.error("Unrecognised format. Is this a supported file type?")
                sys.exit(1)
            match = all_matches[0]
            handler = match.handler
            target = handler.parse(data, src_path)
            # Store alternative candidates for fallback if primary fails
            alt_candidates = [m for m in all_matches[1:] if m.format_id != match.format_id]
    except (ValueError, FileNotFoundError) as exc:
        display.error(f"Format parse error: {exc}")
        sys.exit(1)

    display.target_info(target, handler)

    if not target.is_encrypted:
        return ""

    # GPU probe & Hardware Profiling
    profile = None
    _gpu_device = None
    try:
        from hashaxe.gpu.accelerator import HardwareProfiler, detect_gpu, gpu_info_string

        _gpu_device = detect_gpu()
        profile = HardwareProfiler.auto_profile(_gpu_device)
        if not quiet:
            if profile["has_gpu"]:
                display.ok(
                    f"Hardware Profile: {profile['gpu_name']} "
                    f"({profile['gpu_vram']}MB VRAM, {profile['cpu_cores']} cores)"
                )
            else:
                display.info(f"Hardware Profile: CPU-only ({profile['cpu_cores']} cores)")
    except (ImportError, RuntimeError):
        pass

    cpu_count = multiprocessing.cpu_count()
    if profile:
        n_workers = threads if threads > 0 else profile.get("recommended_workers", cpu_count)
    else:
        n_workers = threads if threads > 0 else cpu_count

    n_workers = min(n_workers, cpu_count * 2)

    # ODF Argon2id requires a single persistent LibreOffice UNO daemon for verification.
    # Multiple workers would each spawn separate soffice processes (~500MB each), consuming
    # massive RAM and racing on file locks. Force single-worker serial mode for this case.
    if target.format_id == "document.odf" and target.format_data.get("kdf") == "argon2id":
        n_workers = 1
        if not quiet:
            display.info("ODF Argon2id detected — using single-worker UNO bridge mode")

    if do_benchmark:
        benchmark(target, match.handler, display, n_workers)
        return None

    # Buffer stdin to temp file so multiprocessing workers can read it
    _stdin_tmpfile = None
    if wordlist == "-":
        import tempfile as _tmpmod

        _stdin_tmpfile = _tmpmod.NamedTemporaryFile(mode="wb", suffix=".wordlist", delete=False)
        for chunk_data in iter(lambda: sys.stdin.buffer.read(65536), b""):
            _stdin_tmpfile.write(chunk_data)
        _stdin_tmpfile.close()
        wordlist = _stdin_tmpfile.name
        display.info(f"Buffered stdin → {wordlist}")

    # ── Attack mode selection (via AttackRegistry if override) ─────────────
    atk_config = AttackConfig(
        wordlist=wordlist,
        wordlist2=wordlist2,
        mask=mask,
        custom_charsets=custom_charsets or {},
        policy=policy,
        markov_order=markov_order,
        prince_min_elems=prince_min,
        prince_max_elems=prince_max,
        ai_candidates=ai_candidates,
    )
    atk_plugin = None

    if attack_mode_override:
        attack_mode = attack_mode_override
        atk_registry = AttackRegistry()
        atk_registry.discover()
        atk_plugin = atk_registry.get(attack_mode)
        if not atk_plugin:
            display.error(f"Unknown attack mode: {attack_mode}")
            sys.exit(1)
        err = atk_plugin.validate_config(atk_config)
        if err:
            display.error(f"Attack config error: {err}")
            sys.exit(1)
        display.info(f"Attack mode: {atk_plugin.attack_name}")
    elif mask and not wordlist:
        attack_mode = "mask"
    elif mask and wordlist:
        attack_mode = "hybrid"
    else:
        attack_mode = "wordlist"
        validate_wordlist(wordlist)

    # AI Generative attacks load 500MB PyTorch contexts. Spawning N workers
    # instantly triggers CUDA Out-Of-Memory. Force single-worker to protect VRAM.
    if attack_mode in ("ai", "osint"):
        n_workers = 1
        if not quiet:
            display.info(
                f"Advanced generation ({attack_mode}) active — restricting to single worker to protect memory and strictly order streams"
            )

    compiled_rules = None
    if rule_file:
        try:
            compiled_rules = load_rule_file(rule_file)
            display.info(f"Loaded {len(compiled_rules)} rules from {rule_file}")
        except FileNotFoundError:
            display.error(f"Rule file not found: {rule_file}")
            sys.exit(1)

    sess_name = session_name or session_name_for(key_path=key_path, wordlist=wordlist or mask or "")
    session = None
    resume_byte = 0

    if restore:
        try:
            session = Session.load(sess_name)
            if session.is_stale():
                display.warn("Session key file changed — starting fresh.")
                session = None
            else:
                resume_byte = session.bytes_done
                display.ok(
                    f"Resuming session '{sess_name}' " f"({session.words_tried:,} already tried)"
                )
        except FileNotFoundError:
            display.warn(f"No session '{sess_name}' found — starting fresh.")

    if session is None:
        session = Session(
            key_path=key_path,
            key_hash=Session.hash_key_file(path=key_path, raw_hash=raw_hash),
            wordlist=wordlist or "",
            mode=attack_mode,
            use_rules=use_rules,
            rule_file=rule_file,
            mask=mask,
        )

    if distributed_master:
        from hashaxe.distributed.master import MasterNode

        result = MasterNode(
            key_path=key_path,
            wordlist=wordlist,
            use_rules=use_rules,
            rule_file=rule_file,
            mask=mask,
            verbose=verbose,
        ).run()
        if result:
            display.found(result, key_path, 0, 0, 0)
        else:
            display.not_found(0, 0)
        return result

    # ── GPU Fast-Hash Dispatch (BEFORE Python workers) ──────────────────────
    # For fast hash types (MD5, SHA1, SHA256, NTLM), if hashcat is installed
    # we delegate entirely to its GPU kernels (4+ GH/s). This is the fix for
    # the 142k pw/s vs 4200 MH/s performance gap.
    if use_gpu:
        try:
            from hashaxe.gpu.fast_hash_cracker import (
                hashcat_available,
                is_fast_hash,
                try_fast_hash_hashaxe_with_display,
            )

            # Only delegate to hashcat if the attack mode is a simple mode that hashcat understands
            # natively via subprocess, and no Python-side rule engines are active.
            supported_hc_modes = {"wordlist", "mask", "hybrid", "combinator"}
            if (
                is_fast_hash(target.format_id)
                and hashcat_available()
                and attack_mode in supported_hc_modes
                and not use_rules
                and not rule_file
            ):
                target_hash = target.format_data.get("target_hash", "")
                if not target_hash and data:
                    try:
                        target_hash = data.decode("utf-8").strip()
                    except Exception:
                        pass
                if target_hash:
                    display.ok("Fast hash detected — routing to hashcat GPU engine")
                    gpu_result, hc_tried, hc_elapsed = try_fast_hash_hashaxe_with_display(
                        target_hash=target_hash,
                        format_id=target.format_id,
                        attack_mode=attack_mode,
                        wordlist=(
                            wordlist
                            if attack_mode in ("wordlist", "hybrid", "combinator")
                            else None
                        ),
                        wordlist2=wordlist2,
                        mask=mask,
                        display=display,
                        total_candidates=(
                            MaskEngine(mask, custom_charsets).candidate_count()
                            if mask and attack_mode == "mask"
                            else 0
                        ),
                        hashcat_mode_override=target.format_data.get("hashcat_mode"),
                    )
                    if gpu_result is not None:
                        display.found(
                            gpu_result,
                            key_path,
                            hc_tried,
                            hc_elapsed,
                            (hc_tried / hc_elapsed) if hc_elapsed > 0 else 0,
                        )
                        session.delete(sess_name)
                        return gpu_result
                    else:
                        display.info("hashcat: not found in keyspace, falling back to CPU")
                        # Fall through to CPU cracking below
        except KeyboardInterrupt:
            display.warn("\nInterrupted — stopping GPU engine...")
            session.update(0, 0)
            session.save(sess_name)
            display.info(f"Session saved as '{sess_name}'. Resume with --restore")
            return None
        except Exception as _gpu_exc:
            display.warn(f"GPU dispatch failed: {_gpu_exc} — falling back to CPU workers")

    from hashaxe.formats.base import CHUNK_SIZES

    perf_chunk = CHUNK_SIZES.get(target.difficulty, 50_000)

    if attack_mode == "mask":
        engine = MaskEngine(mask, custom_charsets)
        total_cands = engine.candidate_count()
        chunk_size = perf_chunk
        n_chunks = max(1, total_cands // chunk_size) + (1 if total_cands % chunk_size > 0 else 0)
        mask_chunks = [
            (i * chunk_size, min((i + 1) * chunk_size, total_cands) - i * chunk_size)
            for i in range(n_chunks)
        ]
        mask_chunks = [(s, c) for s, c in mask_chunks if c > 0]
        display_total = total_cands
    elif attack_mode in ("wordlist", "hybrid"):
        display.info("Indexing wordlist...")
        byte_chunks, total_lines = chunk_wordlist(wordlist, chunk_size_bytes=perf_chunk * 10)
        rule_mult = len(compiled_rules) if compiled_rules else count_rules() if use_rules else 1
        if mask:
            rule_mult *= MaskEngine(mask, custom_charsets).candidate_count()
        display_total = total_lines * rule_mult
    else:
        display.info("Estimating keyspace...")
        display_total = atk_plugin.estimate_keyspace(atk_config) if atk_plugin else 0

    display.attack_header(
        wordlist=wordlist or "(mask only)",
        workers=n_workers,
        use_rules=use_rules,
        total_candidates=display_total,
        mode=attack_mode,
        mask=mask,
        resuming=restore and session is not None,
    )

    # PERF-2: Use direct multiprocessing.Event() (shared memory) instead of
    # Manager().Event() (socket IPC). Every is_set() on a Manager proxy
    # costs a cross-process socket RPC — catastrophic at millions of calls.
    found_event = multiprocessing.Event()
    shared_counter = multiprocessing.Value("i", session.words_tried if restore else 0)

    if attack_mode == "mask":
        work_items = [
            (target, mask, custom_charsets or {}, skip, count) for skip, count in mask_chunks
        ]
        worker_fn = _mask_worker
    elif attack_mode in ("wordlist", "hybrid"):
        work_items = [
            (
                target,
                wordlist,
                start,
                end,
                use_rules,
                compiled_rules,
                mask if attack_mode == "hybrid" else None,
                custom_charsets or {},
                use_smart_order,
            )
            for start, end in byte_chunks
        ]
        worker_fn = _worker
    else:
        import dataclasses

        work_items = [
            (target, attack_mode, dataclasses.asdict(atk_config), i, n_workers)
            for i in range(n_workers)
        ]
        worker_fn = _plugin_worker

    t_start = time.time()
    total_tried = session.words_tried if restore else 0
    result: str | None = None
    last_save = time.time()

    try:
        if use_tui:

            class TUIMonitor:
                def __init__(self, target, mode, display_total, t_start, shared_counter):
                    self.target = target
                    self.mode = mode
                    self.display_total = display_total
                    self.t_start = t_start
                    self.shared_counter = shared_counter

                def snapshot(self):
                    tried = self.shared_counter.value
                    elapsed = time.time() - self.t_start
                    speed = tried / elapsed if elapsed > 0 else 0
                    eta = (self.display_total - tried) / speed if speed > 0 else 0
                    return {
                        "algorithm": self.target.format_id,
                        "attack_mode": self.mode,
                        "rolling_speed": speed,
                        "keyspace_checked": tried,
                        "keyspace_total": self.display_total,
                        "elapsed": f"{elapsed:.1f}s",
                        "eta": f"{eta:.1f}s" if eta > 0 else "Unknown",
                    }

            from hashaxe.tui.app import Dashboard

            monitor = TUIMonitor(target, attack_mode, display_total, t_start, shared_counter)
            dash_ctx = Dashboard(monitor).run()
        else:
            import contextlib

            dash_ctx = contextlib.nullcontext()

        with dash_ctx:
            with multiprocessing.Pool(
                processes=n_workers,
                initializer=_init_worker,
                initargs=(found_event, shared_counter),
            ) as pool:
                poller = None
                if not use_tui:
                    # Start live progress poller thread
                    poller = threading.Thread(
                        target=_progress_poller,
                        args=(
                            shared_counter,
                            found_event,
                            display,
                            display_total,
                            t_start,
                            n_workers,
                        ),
                        daemon=True,
                    )
                    poller.start()

                for pw, tried in pool.imap_unordered(worker_fn, work_items):
                    if pw is not None:
                        result = pw
                        total_tried = shared_counter.value
                        pool.terminate()
                        break

                # Final counter read
                total_tried = shared_counter.value
                found_event.set()  # stop poller
                if poller:
                    poller.join(timeout=1.0)

                if time.time() - last_save >= 30:
                    session.update(0, total_tried)
                    session.save(sess_name)

    except KeyboardInterrupt:
        total_tried = shared_counter.value
        found_event.set()  # stop poller
        display.warn("\nInterrupted — saving session...")
        session.update(0, total_tried)
        session.save(sess_name)
        display.info(f"Session saved as '{sess_name}'. Resume with --restore")
        return None

    elapsed = time.time() - t_start
    total_elapsed = session.elapsed + elapsed
    speed = total_tried / total_elapsed if total_elapsed > 0 else 0

    if result is not None:
        try:
            from hashaxe.db import CrackDB

            CrackDB().log_hashaxe(
                format_id=target.format_id,
                passphrase=result,
                source_path=key_path,
                format_name=target.display_name,
                attack_mode=attack_mode,
                wordlist_path=wordlist if attack_mode != "mask" else None,
                rule_file=rule_file,
                mask_pattern=mask,
                candidates=total_tried,
                elapsed_sec=total_elapsed,
                speed_pw_s=speed,
                workers=n_workers,
                gpu_model="GPU" if use_gpu else None,
            )
        except Exception as e:
            display.warn(f"Failed to log hashaxe to database: {e}")

        display.found(result, key_path, total_tried, total_elapsed, speed)
        session.delete(sess_name)
        if output:
            Path(output).write_text(
                f"KEY: {key_path}\nPASSPHRASE: {result}\n"
                f"TIME: {total_elapsed:.2f}s\nTRIED: {total_tried}\n"
            )
            display.ok(f"Result saved to {output}")
        if verify_host and verify_user:
            display.info("Verifying via live SSH...")
            ok = _verify_ssh(verify_host, verify_port, verify_user, key_path, result)
            display.ssh_verify(ok)
        return result
    else:
        # ── Format Fallback ──────────────────────────────────────────────
        # If the primary format didn't hashaxe, try alternative formats.
        # This resolves ambiguous formats like 32hex:username which could
        # be PostgreSQL MD5 (hashcat -m 12) or DCC MS Cache v1 (-m 1100).
        if (
            alt_candidates
            and (wordlist or (attack_mode == "mask" and mask))
            and not format_override
        ):
            for alt_match in alt_candidates:
                alt_handler = alt_match.handler
                try:
                    alt_target = alt_handler.parse(data, src_path)
                except Exception:
                    continue
                if not alt_target.is_encrypted:
                    continue
                display.info(f"Retrying with alternative format: {alt_target.display_name}")
                alt_found = None
                try:
                    if wordlist:
                        # Lightweight serial verify against wordlist
                        with open(wordlist, encoding="utf-8", errors="ignore") as wf:
                            for line in wf:
                                pw = line.rstrip("\n\r")
                                if not pw:
                                    continue
                                if alt_handler.verify(alt_target, pw.encode("utf-8")):
                                    alt_found = pw
                                    break
                    elif attack_mode == "mask" and mask:
                        # Lightweight serial verify against mask candidates
                        alt_engine = MaskEngine(mask, custom_charsets or {})
                        for candidate in alt_engine.candidates():
                            if alt_handler.verify(alt_target, candidate.encode("utf-8")):
                                alt_found = candidate
                                break
                except Exception:
                    continue
                if alt_found is not None:
                    elapsed = time.time() - t_start
                    total_elapsed = session.elapsed + elapsed
                    speed = total_tried / total_elapsed if total_elapsed > 0 else 0
                    display.found(alt_found, key_path, total_tried, total_elapsed, speed)
                    session.delete(sess_name)
                    return alt_found

        display.not_found(total_tried, total_elapsed)
        return None


def _verify_ssh(host, port, user, key_path, passphrase):
    try:
        import paramiko
    except ImportError:
        print("  paramiko not installed — pip install paramiko")
        return False
    try:
        c = paramiko.SSHClient()
        # AutoAddPolicy is intentional for an offensive tool — pentest targets
        # are ad-hoc machines whose host keys are rarely pre-known.
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Skip load_system_host_keys — stale entries conflict with new targets.
        c.connect(
            hostname=host,
            port=port,
            username=user,
            key_filename=key_path,
            passphrase=passphrase,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        c.close()
        return True
    except Exception as e:
        print(f"  SSH Verification failed: {e}")
        return False
