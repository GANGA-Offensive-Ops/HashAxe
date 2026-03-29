# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/gpu/fast_hash_cracker.py
#  GPU-native dispatch for fast hash types (MD5, SHA-*, NTLM).
#  Prioritizes hashcat subprocess; falls back to custom pycuda/pyopencl kernels.
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
gpu/fast_hash_cracker.py — GPU-native dispatch for fast hash types.

This module is the MISSING LINK between the fast hash format handlers
(MD5, SHA1, SHA256, NTLM, SHA384, SHA512) and the actual GPU.

Architecture Decision:
We use a dual-path strategy:
  1. hashcat subprocess (PREFERRED): If hashcat is installed, we delegate
     MD5/SHA1/NTLM/SHA256 cracking to hashcat via subprocess. This gives
     4+ GH/s on RTX 3050 with zero custom GPU kernel code needed.
     Hashcat uses highly optimised PTX kernels for every hash type.

  2. pycuda/pyopencl native (FUTURE): If hashcat is NOT available,
     we use our custom CUDA kernel (gpu/kernels/md5.cu) via pycuda.

Why hashcat subprocess first?
  - Our md5.cu kernel is ~500x slower than hashcat's optimised kernel.
  - Hashcat's pure-kernel does 4196 MH/s. Our Python pycuda dispatch
    would top out at ~50 MH/s due to PCIe transfer overhead per batch.
  - Delegating to hashcat is the battle-tested approach used by many
    professional frameworks (e.g. Wifite, Airhashaxe wrappers).

The cracker.py integration:
  Before spawning Python multiprocessing workers, cracker.py should call
  `try_fast_hash_hashaxe()`. If it succeeds or fails definitively, it returns.
  Only if hashcat is not available does it fall through to Python CPU workers.

GANGA Offensive Ops · Hashaxe V1
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

# ── Hashcat mode map ──────────────────────────────────────────────────────────
# Derived from the central hash registry — single source of truth.
# All GPU-routable formats are automatically included.
from hashaxe.core.hash_registry import get_all_hashcat_modes as _get_all_hashcat_modes

HASHCAT_MODES: dict[str, int] = _get_all_hashcat_modes()
HASHCAT_MODES["hash.raw"] = 0  # fallback for generic raw hashes

# ── hashcat attack mode map ───────────────────────────────────────────────────
# Maps our attack_mode → hashcat -a number
HASHCAT_ATTACK_MODES: dict[str, int] = {
    "wordlist": 0,
    "combinator": 1,
    "mask": 3,
    "hybrid": 6,
}

# ── Mask charset translation ──────────────────────────────────────────────────
# Our mask syntax uses the same ?l?u?d?s as hashcat — no translation needed.


def hashcat_available() -> bool:
    """Check if hashcat is installed and reachable."""
    try:
        result = subprocess.run(["/usr/bin/hashcat", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        result = subprocess.run(["hashcat", "--version"], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _find_hashcat() -> str:
    """Return the absolute path to hashcat binary."""
    for path in ["/usr/bin/hashcat", "/usr/local/bin/hashcat"]:
        if os.path.isfile(path):
            return path
    return "hashcat"  # fallback to PATH


def is_fast_hash(format_id: str) -> bool:
    """Return True if this format should be GPU-accelerated via hashcat."""
    return format_id in HASHCAT_MODES


def try_fast_hash_hashaxe(
    target_hash: str,
    format_id: str,
    attack_mode: str,
    wordlist: str | None = None,
    wordlist2: str | None = None,
    mask: str | None = None,
    display=None,
    on_progress=None,
) -> str | None:
    """
    Attempt to hashaxe a fast hash using hashcat as the GPU backend.

    Returns the cracked plaintext on success, None on failure/not found.

    Parameters:
        target_hash  — The hex hash string (e.g. "5f4dcc3b...")
        format_id    — Our format ID (e.g. "hash.md5")
        attack_mode  — "wordlist", "mask", "hybrid", or "combinator"
        wordlist     — Path to wordlist file (for wordlist/hybrid/combinator modes)
        wordlist2    — Path to second wordlist file (for combinator mode)
        mask         — Mask pattern (for mask/hybrid modes)
        display      — Optional Display object for status output
        on_progress  — Optional callback(tried, speed_str) for progress

    This function:
      1. Writes the hash to a temp file
      2. Constructs the hashcat command
      3. Runs hashcat with --potfile-disable so we see the result in stdout
      4. Parses the "cracked" output line
      5. Returns the plaintext
    """
    hc_mode = HASHCAT_MODES.get(format_id, 0)
    hc_atk = HASHCAT_ATTACK_MODES.get(attack_mode, 3)
    hc_bin = _find_hashcat()

    # Write hash to temp file
    hash_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(target_hash.strip() + "\n")
            hash_file = f.name

        cmd = [
            hc_bin,
            "-m",
            str(hc_mode),
            "-a",
            str(hc_atk),
            "--potfile-disable",  # Don't cache — we want live output
            "--status",  # Periodic status updates
            "--status-timer=3",  # Every 3 seconds
            hash_file,
        ]

        if attack_mode == "wordlist" and wordlist:
            cmd.append(wordlist)
        elif attack_mode == "combinator" and wordlist and wordlist2:
            cmd.extend([wordlist, wordlist2])
        elif attack_mode == "mask" and mask:
            cmd.append(mask)
        elif attack_mode == "hybrid" and wordlist and mask:
            cmd.extend([wordlist, mask])

        if display:
            display.info(f"Delegating to hashcat GPU backend (mode -m {hc_mode} -a {hc_atk})")
            display.info(f"Command: {' '.join(cmd)}")

        result_pw = None
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        found_re = re.compile(r"^(.+?):(.+)$", re.MULTILINE)

        try:
            stdout_data, stderr_data = proc.communicate(timeout=7200)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_data, stderr_data = proc.communicate()

        normalized_hash = target_hash.lower().strip()
        for line in stdout_data.splitlines():
            m = found_re.match(line)
            line_lower = line.lower()
            if line_lower.startswith(normalized_hash + ":"):
                return line[len(normalized_hash) + 1 :].strip()
            elif format_id == "hash.lm" and (
                line_lower.startswith(normalized_hash[:16] + ":")
                or line_lower.startswith(normalized_hash[16:] + ":")
            ):
                return line.split(":", 1)[1].strip()

        # ── NTLM/LM fallback for ambiguous 32-hex hashes ────────────────
        # MD5 and NTLM are both 32-hex chars. If MD5 mode (0) failed,
        # automatically retry with NTLM mode (1000), then LM mode (3000).
        if format_id == "hash.md5" and len(normalized_hash) == 32:
            for fallback_mode, fallback_name in [(1000, "NTLM"), (3000, "LM")]:
                if display:
                    display.info(
                        f"Checking ambiguous 32-hex hash against {fallback_name} (mode {fallback_mode})..."
                    )
                fb_hash_file = None
                try:
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
                        f.write(target_hash.strip() + "\n")
                        fb_hash_file = f.name

                    fb_cmd = [
                        hc_bin,
                        "-m",
                        str(fallback_mode),
                        "-a",
                        str(hc_atk),
                        "--potfile-disable",
                        "--status",
                        "--status-timer=3",
                        fb_hash_file,
                    ]
                    if attack_mode == "wordlist" and wordlist:
                        fb_cmd.append(wordlist)
                    elif attack_mode == "combinator" and wordlist and wordlist2:
                        fb_cmd.extend([wordlist, wordlist2])
                    elif attack_mode == "mask" and mask:
                        fb_cmd.append(mask)
                    elif attack_mode == "hybrid" and wordlist and mask:
                        fb_cmd.extend([wordlist, mask])

                    fb_proc = subprocess.Popen(
                        fb_cmd,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                    )
                    try:
                        fb_stdout, fb_stderr = fb_proc.communicate(timeout=7200)
                    except subprocess.TimeoutExpired:
                        fb_proc.kill()
                        fb_stdout, fb_stderr = fb_proc.communicate()

                    for line in fb_stdout.splitlines():
                        fm = found_re.match(line)
                        line_lower = line.lower()
                        if line_lower.startswith(normalized_hash + ":"):
                            return line[len(normalized_hash) + 1 :].strip()
                        elif format_id == "hash.lm" and (
                            line_lower.startswith(normalized_hash[:16] + ":")
                            or line_lower.startswith(normalized_hash[16:] + ":")
                        ):
                            return line.split(":", 1)[1].strip()
                finally:
                    if fb_hash_file and os.path.exists(fb_hash_file):
                        os.unlink(fb_hash_file)

        return None

    finally:
        if hash_file and os.path.exists(hash_file):
            os.unlink(hash_file)


def try_fast_hash_hashaxe_with_display(
    target_hash: str,
    format_id: str,
    attack_mode: str,
    wordlist: str | None = None,
    wordlist2: str | None = None,
    mask: str | None = None,
    display=None,
    total_candidates: int = 0,
    hashcat_mode_override: int | None = None,
) -> tuple[str | None, int, float]:
    """
    Wrapper around try_fast_hash_hashaxe that integrates with the Display class.
    Shows real-time speed from hashcat's status output.
    Returns: (found_plaintext, total_tried_candidates, elapsed_seconds)

    hashcat_mode_override: If set, overrides the registry mode for this format.
                          Used by PDF handler to specify revision-specific modes.
    """
    hc_mode = (
        hashcat_mode_override
        if hashcat_mode_override is not None
        else HASHCAT_MODES.get(format_id, 0)
    )
    hc_atk = HASHCAT_ATTACK_MODES.get(attack_mode, 3)
    hc_bin = _find_hashcat()

    if not hc_bin:
        raise RuntimeError("hashcat binary not found")

    if attack_mode == "wordlist" and not wordlist:
        raise ValueError("wordlist path required for wordlist attack mode")
    if attack_mode == "combinator" and not (wordlist and wordlist2):
        raise ValueError("wordlist and wordlist2 paths required for combinator attack mode")
    if attack_mode == "mask" and not mask:
        raise ValueError("mask required for mask attack mode")
    if attack_mode == "hybrid" and not (wordlist and mask):
        raise ValueError("wordlist and mask both required for hybrid attack mode")

    if display:
        display.info(f"GPU Backend: hashcat (mode {hc_mode}, attack {hc_atk})")
        display.ok("Routing to GPU via hashcat — expect GH/s speeds!")

    hash_file = None
    try:
        safe_hash = target_hash.strip().replace("\n", "").replace("\r", "")
        normalized_hash = safe_hash.lower()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(safe_hash + "\n")
            hash_file = f.name

        cmd = [
            hc_bin,
            "-m",
            str(hc_mode),
            "-a",
            str(hc_atk),
            "--potfile-disable",
            "--status",
            "--status-timer=3",
            hash_file,
        ]

        if attack_mode == "wordlist" and wordlist:
            cmd.append(wordlist)
        elif attack_mode == "combinator" and wordlist and wordlist2:
            cmd.extend([wordlist, wordlist2])
        elif attack_mode == "mask" and mask:
            cmd.append(mask)
        elif attack_mode == "hybrid" and wordlist and mask:
            cmd.extend([wordlist, mask])

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            stdin=subprocess.DEVNULL,
        )

        if proc.stdout is None:
            raise RuntimeError("Failed to open hashcat stdout pipe")

        # group(1) = hash, group(2) = password (passwords may contain colons,
        # so .+ is intentional — we match on the hash side only)
        found_re = re.compile(r"^(.+?):(.+)$", re.MULTILINE)
        speed_re = re.compile(r"Speed\.#\d+\.*:\s+([\d.]+\s+[GMKk]?H/s)")
        prog_re = re.compile(r"Progress\.*:\s+(\d+)/(\d+)\s+\(([\d.]+)%\)")

        all_lines = []
        found_pw = None
        last_speed = ""
        last_speed_val = 0.0
        max_tried = 0
        t0 = time.time()

        try:
            for line in proc.stdout:
                line = line.rstrip()
                all_lines.append(line)

                # Speed
                m = speed_re.search(line)
                if m:
                    last_speed = m.group(1)
                    try:
                        v = float(last_speed.split()[0])
                        if "kH/s" in last_speed:
                            v *= 1000
                        elif "MH/s" in last_speed:
                            v *= 1000000
                        elif "GH/s" in last_speed:
                            v *= 1000000000
                        last_speed_val = v
                    except ValueError:
                        last_speed_val = 0.0

                # Progress
                m_prog = prog_re.search(line)
                if m_prog:
                    current = int(m_prog.group(1))
                    total_hc = int(m_prog.group(2))
                    max_tried = max(max_tried, current, total_hc)
                    if display and not display.quiet:
                        display.progress(current, total_hc or total_candidates, last_speed_val, 1)
                elif m and display and not display.quiet:
                    display.progress(0, total_candidates, last_speed_val, 1)

                # Found
                m = found_re.match(line)
                line_lower = line.lower()
                if line_lower.startswith(normalized_hash + ":"):
                    found_pw = line[len(normalized_hash) + 1 :].strip()
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    break
                elif format_id == "hash.lm" and (
                    line_lower.startswith(normalized_hash[:16] + ":")
                    or line_lower.startswith(normalized_hash[16:] + ":")
                ):
                    found_pw = line.split(":", 1)[1].strip()
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    break

            else:
                # Normal exit — no break
                proc.wait()
        except KeyboardInterrupt:
            # Graceful shutdown: kill hashcat subprocess cleanly
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise  # Re-raise so cracker.py can handle session saving

        # Re-scan buffered lines in case the cracked line arrived just before
        # the stream ended and was not caught above (e.g. no-break path)
        if found_pw is None:
            for line in all_lines:
                m = found_re.match(line)
                line_lower = line.lower()
                if line_lower.startswith(normalized_hash + ":"):
                    found_pw = line[len(normalized_hash) + 1 :].strip()
                    break
                elif format_id == "hash.lm" and (
                    line_lower.startswith(normalized_hash[:16] + ":")
                    or line_lower.startswith(normalized_hash[16:] + ":")
                ):
                    found_pw = line.split(":", 1)[1].strip()
                    break
                elif line.strip() and ":" not in line and proc.returncode == 0:
                    # If hashcat cracked it instantly it might just print the password
                    if target_hash[:8].lower() in line.lower() or target_hash in all_lines:
                        pass  # too broad

            if not found_pw and "INFO: All hashes found in potfile" in "\n".join(all_lines):
                # Hashcat already cracked this earlier and cached it despite potfile-disable (if it was somehow left)
                pass

            # ── NTLM/LM fallback for ambiguous 32-hex hashes ────────────────
            if not found_pw and format_id == "hash.md5" and len(normalized_hash) == 32:
                for fb_mode, fb_name in [(1000, "NTLM"), (3000, "LM")]:
                    if display:
                        display.info(
                            f"Checking ambiguous 32-hex hash against {fb_name} (mode {fb_mode})..."
                        )

                    fb_cmd = [
                        hc_bin,
                        "-m",
                        str(fb_mode),
                        "-a",
                        str(hc_atk),
                        "--potfile-disable",
                        "--status",
                        "--status-timer=3",
                        hash_file,
                    ]
                    if attack_mode == "wordlist" and wordlist:
                        fb_cmd.append(wordlist)
                    elif attack_mode == "combinator" and wordlist and wordlist2:
                        fb_cmd.extend([wordlist, wordlist2])
                    elif attack_mode == "mask" and mask:
                        fb_cmd.append(mask)
                    elif attack_mode == "hybrid" and wordlist and mask:
                        fb_cmd.extend([wordlist, mask])

                    fb_proc = subprocess.Popen(
                        fb_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        stdin=subprocess.DEVNULL,
                    )

                    fb_all_lines = []
                    try:
                        for line in fb_proc.stdout:
                            line = line.rstrip()
                            fb_all_lines.append(line)
                            m_prog = prog_re.search(line)
                            if m_prog:
                                c = int(m_prog.group(1))
                                t = int(m_prog.group(2))
                                max_tried = max(max_tried, c, t)
                                if display and not display.quiet:
                                    display.progress(c, t or total_candidates, 0, 1)

                            line_lower = line.lower()
                            if line_lower.startswith(normalized_hash + ":"):
                                found_pw = line[len(normalized_hash) + 1 :].strip()
                                fb_proc.terminate()
                                try:
                                    fb_proc.wait(timeout=2)
                                except subprocess.TimeoutExpired:
                                    fb_proc.kill()
                                break
                            elif fb_mode == 3000 and (
                                line_lower.startswith(normalized_hash[:16] + ":")
                                or line_lower.startswith(normalized_hash[16:] + ":")
                            ):
                                found_pw = line.split(":", 1)[1].strip()
                                fb_proc.terminate()
                                try:
                                    fb_proc.wait(timeout=2)
                                except subprocess.TimeoutExpired:
                                    fb_proc.kill()
                                break
                        else:
                            fb_proc.wait()
                    except KeyboardInterrupt:
                        fb_proc.terminate()
                        try:
                            fb_proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            fb_proc.kill()
                            fb_proc.wait()
                        raise

                    if not found_pw:
                        for line in fb_all_lines:
                            line_lower = line.lower()
                            if line_lower.startswith(normalized_hash + ":"):
                                found_pw = line[len(normalized_hash) + 1 :].strip()
                                break
                            elif fb_mode == 3000 and (
                                line_lower.startswith(normalized_hash[:16] + ":")
                                or line_lower.startswith(normalized_hash[16:] + ":")
                            ):
                                found_pw = line.split(":", 1)[1].strip()
                                break

                    if found_pw:
                        break

        if found_pw and max_tried == 0:
            max_tried = 1
        return found_pw, max_tried, (time.time() - t0)

    finally:
        if hash_file and os.path.exists(hash_file):
            os.unlink(hash_file)


# ── Pre-compiled libhashaxe_engine fast hash dispatch ───────────────────────────

_LIBCRACK_ENGINE = None
_LIBCRACK_HASH_TYPES = {"md5": 0, "ntlm": 1, "sha256": 2}


def _load_libhashaxe_engine():
    """Load the pre-compiled libhashaxe_engine.so shared library."""
    global _LIBCRACK_ENGINE
    if _LIBCRACK_ENGINE is not None:
        return _LIBCRACK_ENGINE
    try:
        import ctypes

        lib_path = (
            Path(__file__).parent.parent / "native" / "libhashaxe_engine" / "libhashaxe_engine.so"
        )
        if not lib_path.exists():
            return None
        lib = ctypes.CDLL(str(lib_path))
        lib.engine_fast_hash_hashaxe.restype = ctypes.c_int
        lib.engine_fast_hash_hashaxe.argtypes = [
            ctypes.c_int,  # hash_type
            ctypes.POINTER(ctypes.c_uint8),  # candidates
            ctypes.POINTER(ctypes.c_int),  # lengths
            ctypes.c_int,  # num_candidates
            ctypes.POINTER(ctypes.c_uint8),  # target_hash
            ctypes.c_int,  # target_hash_bytes
        ]
        _LIBCRACK_ENGINE = lib
        return lib
    except Exception:
        return None


def run_libhashaxe_fast_hash(
    hash_type_name: str,
    target_hash: str,
    candidates: list[str],
) -> str | None:
    """
    Use pre-compiled CUDA kernels in libhashaxe_engine.so for fast hash cracking.
    Eliminates PyCUDA JIT compilation overhead entirely.

    hash_type_name: 'md5', 'ntlm', or 'sha256'
    target_hash: hex string of the target hash
    candidates: list of password strings to test

    Returns the matching password string, or None.
    """
    import ctypes

    import numpy as np

    lib = _load_libhashaxe_engine()
    if lib is None:
        return None

    hash_type = _LIBCRACK_HASH_TYPES.get(hash_type_name)
    if hash_type is None:
        return None

    try:
        n = len(candidates)
        MAX_LEN = 64

        # Build flat candidate array (n × 64 bytes)
        pw_flat = np.zeros(n * MAX_LEN, dtype=np.uint8)
        lengths = np.zeros(n, dtype=np.int32)
        for i, c in enumerate(candidates):
            b = c.encode("utf-8", "replace")[:MAX_LEN]
            offset = i * MAX_LEN
            pw_flat[offset : offset + len(b)] = list(b)
            lengths[i] = len(b)

        # Parse target hash
        target_bytes = bytes.fromhex(target_hash)
        target_arr = np.frombuffer(target_bytes, dtype=np.uint8).copy()

        # Call into pre-compiled CUDA
        result = lib.engine_fast_hash_hashaxe(
            hash_type,
            pw_flat.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8)),
            lengths.ctypes.data_as(ctypes.POINTER(ctypes.c_int)),
            n,
            target_arr.ctypes.data_as(ctypes.POINTER(ctypes.c_uint8)),
            len(target_bytes),
        )

        if result >= 0:
            return candidates[result]
    except Exception as e:
        import logging

        logging.getLogger(__name__).warning("Native libhashaxe_engine dispatch failed: %s", e)

    return None


_CUDA_CTX = None


def _ensure_cuda_context():
    global _CUDA_CTX
    if _CUDA_CTX is None:
        import pycuda.driver as drv

        drv.init()
        _CUDA_CTX = drv.Device(0).make_context()
    return _CUDA_CTX


def run_pycuda_md5_hashaxe(
    target_hash: str,
    candidates: list[str],
) -> str | None:
    """
    Run the custom CUDA MD5 kernel (gpu/kernels/md5.cu) against a batch
    of candidates. Used when hashcat is not available.

    NOTE: This only handles passwords up to 55 bytes (single MD5 block).
    For longer passwords, fall back to Python hashlib.
    """
    try:
        import numpy as np

        _ensure_cuda_context()
        import pycuda.compiler as compiler
        import pycuda.driver as drv

        # Compile kernel
        kernel_path = Path(__file__).parent / "kernels" / "md5.cu"
        src = kernel_path.read_text()
        mod = compiler.SourceModule(src, options=["-O3"])
        md5_kernel = mod.get_function("md5_hashaxeKernel")

        # Parse target hash into uint32[4]
        target_bytes = bytes.fromhex(target_hash)
        target_u32 = np.frombuffer(target_bytes, dtype=np.dtype("<u4"))

        # Build candidate array
        n = len(candidates)
        MAX_LEN = 64
        pw_flat = np.zeros((n, MAX_LEN), dtype=np.uint8)
        lengths = np.zeros(n, dtype=np.int32)

        for i, c in enumerate(candidates):
            b = c.encode("utf-8", "replace")[:MAX_LEN]
            pw_flat[i, : len(b)] = list(b)
            lengths[i] = len(b)

        found_idx = np.array([-1], dtype=np.int32)

        # GPU dispatch
        pw_gpu = drv.to_device(pw_flat.flatten())
        lens_gpu = drv.to_device(lengths)
        tgt_gpu = drv.to_device(target_u32)
        found_gpu = drv.to_device(found_idx)

        BLOCK = 256
        grid = (n + BLOCK - 1) // BLOCK

        md5_kernel(
            pw_gpu,
            lens_gpu,
            np.int32(MAX_LEN),
            np.int32(n),
            tgt_gpu,
            found_gpu,
            block=(BLOCK, 1, 1),
            grid=(grid, 1),
        )

        result = drv.from_device(found_gpu, (1,), np.int32)
        if result[0] >= 0:
            return candidates[result[0]]

    except Exception:
        pass  # Fall back to caller's CPU loop

    return None
