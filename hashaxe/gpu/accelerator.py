# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/gpu/accelerator.py
#  GPU detection, capability probing, and hybrid CPU+GPU dispatch pipeline.
#  CPU handles bcrypt-KDF, GPU handles AES/ChaCha batch decryption with checkints.
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
gpu/accelerator.py — GPU detection, capability probing, and dispatch.

Architecture
============
bcrypt-KDF is the bottleneck. It cannot be trivially parallelised because
each call is intentionally sequential (serial SHA-512 rounds).

Our GPU strategy: HYBRID CPU+GPU PIPELINE
──────────────────────────────────────────
                    Wordlist Chunk
                         │
                    bcrypt-KDF      ← CPU multiprocessing (parallel per word)
                    (key material)
                         │
              ┌──────────▼──────────┐
              │  AES/ChaCha decrypt  │  ← GPU batch (1024 candidates/dispatch)
              │  checkints test      │    massive memory bandwidth advantage
              └──────────┬──────────┘
                         │
                    MATCH?  → full confirm → FOUND

Why this works:
  - bcrypt dominates at ~200ms/attempt on CPU
  - AES checkints is nanoseconds — barely worth GPUing alone
  - BUT: GPU enables bcrypt parallelism across thousands of CUDA cores
  - Real speedup comes from running bcrypt on thousands of GPU threads
    simultaneously using John-the-Ripper's GPU bcrypt approach

Supported backends (in priority order):
  1. CUDA          (NVIDIA — ctypes + compiled PTX)
  2. OpenCL        (NVIDIA/AMD/Intel — pyopencl)
  3. Metal         (Apple Silicon — unavailable on Linux)
  4. CPU fallback  (always available — numpy SIMD batching)

Speed estimates:
  RTX 3050  → ~50,000 pw/s   (OpenCL, 16 rounds)
  RTX 3090  → ~120,000 pw/s  (CUDA)
  RTX 4090  → ~200,000 pw/s  (CUDA, Ada Lovelace)
  4× RTX 4090 → ~800,000 pw/s (distributed, see distributed/)
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import List, Optional

# ── Backend enum ──────────────────────────────────────────────────────────────

class GPUBackend(Enum):
    CUDA    = auto()
    OPENCL  = auto()
    NONE    = auto()   # CPU fallback


# ── Device info ───────────────────────────────────────────────────────────────

@dataclass
class GPUDevice:
    backend:       GPUBackend
    name:          str        = "Unknown"
    vendor:        str        = ""
    compute_units: int        = 0
    global_mem_mb: int        = 0
    driver_version:str        = ""
    est_speed_pw_s:float      = 0.0    # estimated pw/s at 16 rounds bcrypt

    # Convenience aliases for cleaner API
    @property
    def vram_mb(self) -> int:
        return self.global_mem_mb

    @property
    def estimated_pw_per_sec(self) -> float:
        return self.est_speed_pw_s


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_gpu() -> GPUDevice | None:
    """
    Probe the system for a compatible GPU and return a GPUDevice descriptor.
    Returns None if no GPU is detected or no supported driver is available.

    Detection order:
      1. CUDA via nvidia-smi + libcuda.so
      2. OpenCL via pyopencl (cross-vendor)
      3. None
    """
    device = _try_cuda()
    if device:
        return device

    device = _try_opencl()
    if device:
        return device

    return None


def _try_cuda() -> GPUDevice | None:
    """Attempt NVIDIA CUDA detection via nvidia-smi."""
    try:
        # SECURITY FIX: Use absolute path to prevent PATH hijacking
        out = subprocess.check_output(
            ["/usr/bin/nvidia-smi",
             "--query-gpu=name,driver_version,memory.total,compute_cap",
             "--format=csv,noheader,nounits"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()
        if not out:
            return None

        parts = [p.strip() for p in out.split(",")]
        name        = parts[0] if len(parts) > 0 else "NVIDIA GPU"
        driver_ver  = parts[1] if len(parts) > 1 else "?"
        mem_mb      = int(parts[2]) if len(parts) > 2 else 0
        compute_cap = parts[3] if len(parts) > 3 else "?"

        return GPUDevice(
            backend        = GPUBackend.CUDA,
            name           = name,
            vendor         = "NVIDIA",
            global_mem_mb  = mem_mb,
            driver_version = driver_ver,
            est_speed_pw_s = 0.0,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired,
            subprocess.CalledProcessError):
        return None


def _try_opencl() -> GPUDevice | None:
    """Attempt OpenCL detection via pyopencl."""
    try:
        import pyopencl as cl
        platforms = cl.get_platforms()
        if not platforms:
            return None

        # Pick the first GPU device
        for platform in platforms:
            try:
                devices = platform.get_devices(device_type=cl.device_type.GPU)
            except cl.Error:
                continue
            if devices:
                dev = devices[0]
                name   = dev.name.strip()
                vendor = dev.vendor.strip()
                mem_mb = dev.global_mem_size // (1024 * 1024)
                cu     = dev.max_compute_units
                return GPUDevice(
                    backend        = GPUBackend.OPENCL,
                    name           = name,
                    vendor         = vendor,
                    compute_units  = cu,
                    global_mem_mb  = mem_mb,
                    est_speed_pw_s = 0.0,
                )
    except ImportError:
        pass
    except Exception:
        pass

    return None


def live_benchmark(pk, duration: float = 3.0) -> float:
    """
    Run a real benchmark: test actual try_passphrase() calls against
    the given key for `duration` seconds.
    Returns measured speed in pw/s (per-core).
    """
    import time

    from hashaxe.engine import try_passphrase

    passwords = [f"__bench_{i:06d}__".encode() for i in range(500)]
    t0     = time.perf_counter()
    tested = 0
    for pw in passwords * 20:
        try_passphrase(pk, pw)
        tested += 1
        if time.perf_counter() - t0 >= duration:
            break
    elapsed = time.perf_counter() - t0
    return tested / elapsed if elapsed > 0 else 0.0


# ── GPU cracker session ───────────────────────────────────────────────────────

class GPUCracker:
    """
    Manages a GPU cracking session.

    For systems WITH a compatible GPU:
      • Compiles/loads the kernel at init time
      • Dispatches candidate batches to the GPU
      • Returns match or None

    For systems WITHOUT a GPU (this environment):
      • Falls back gracefully to the CPU numpy SIMD path (see cpu/simd.py)
      • Issues a one-time warning
    """

    def __init__(self, device: GPUDevice | None = None):
        self.device  = device or detect_gpu()
        self.backend = self.device.backend if self.device else GPUBackend.NONE
        self._ctx    = None
        self._prog   = None
        self._warned = False
        self._lib    = None
        self._engine_ctx = None
        self._using_libhashaxe = False
        self._max_batch = 8192
        self._max_pw = 72
        
        if self.backend == GPUBackend.CUDA:
            self._init_cuda()
        elif self.backend == GPUBackend.OPENCL:
            self._init_opencl()
        else:
            self._warn_no_gpu()

    def _warn_no_gpu(self):
        if not self._warned:
            print(
                "\033[93m[!]\033[0m No compatible GPU detected.\n"
                "    Falling back to CPU SIMD mode (numpy batching).\n"
                "    For GPU support:\n"
                "      NVIDIA: Install CUDA toolkit + pip install pycuda\n"
                "      Any GPU: pip install pyopencl\n"
                "      Cloud:   See docs/GPU_SETUP.md for AWS G5 instructions\n"
            )
            self._warned = True

    def _init_cuda(self):
        """Compile and cache the CUDA PTX kernel or load libhashaxe_engine."""
        engine_path = Path(__file__).parent.parent / "native" / "libhashaxe_engine" / "libhashaxe_engine.so"
        if engine_path.exists():
            try:
                self._lib = ctypes.CDLL(str(engine_path))
                self._lib.engine_init.restype = ctypes.c_void_p
                self._lib.engine_init.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
                self._lib.engine_get_pw_flat.restype = ctypes.POINTER(ctypes.c_uint8)
                self._lib.engine_get_pw_lens.restype = ctypes.POINTER(ctypes.c_int)
                self._lib.engine_get_results.restype = ctypes.POINTER(ctypes.c_uint8)
                self._lib.engine_launch.argtypes = [
                    ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                    ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                    ctypes.c_int, ctypes.c_int,
                    ctypes.c_char_p, ctypes.c_int
                ]
                
                self._max_batch = 8192
                self._max_pw    = 72
                self._engine_ctx = self._lib.engine_init(0, self._max_batch, self._max_pw)
                self._using_libhashaxe = True
                return
            except Exception as e:
                print(f"\033[93m[!]\033[0m Failed to load libhashaxe_engine.so: {e}. Falling back to PyCUDA.")
        
        self._using_libhashaxe = False
        try:
            import pycuda.compiler as compiler
            import pycuda.driver as drv
            drv.init()
            self._cuda_ctx = drv.Device(0).make_context()
            kernel_path = Path(__file__).parent / "cuda_kernel.cu"
            src = kernel_path.read_text()
            mod = compiler.SourceModule(src, options=["-O3", "-arch=sm_86"])
            self._cuda_fn = mod.get_function("hashaxe_bcrypt_ssh")
        except Exception as exc:
            print(f"\033[93m[!]\033[0m CUDA init failed: {exc}\n"
                  f"    Falling back to CPU mode.")
            self.backend = GPUBackend.NONE
            self._warn_no_gpu()

    def __del__(self):
        if getattr(self, "_using_libhashaxe", False) and getattr(self, "_engine_ctx", None):
            if hasattr(self, "_lib"):
                self._lib.engine_destroy(self._engine_ctx)
        elif hasattr(self, "_cuda_ctx") and self._cuda_ctx is not None:
            try:
                self._cuda_ctx.pop()
            except Exception:
                pass

    def _init_opencl(self):
        """Compile and cache the OpenCL kernel."""
        try:
            import pyopencl as cl
            platforms = cl.get_platforms()
            for p in platforms:
                devs = p.get_devices(cl.device_type.GPU)
                if devs:
                    self._ctx  = cl.Context(devs[:1])
                    self._queue= cl.CommandQueue(self._ctx)
                    kernel_path = Path(__file__).parent / "opencl_kernel.cl"
                    src  = kernel_path.read_text()
                    self._prog = cl.Program(self._ctx, src).build()
                    return
        except Exception as exc:
            print(f"\033[93m[!]\033[0m OpenCL init failed: {exc}\n"
                  f"    Falling back to CPU mode.")
            self.backend = GPUBackend.NONE
            self._warn_no_gpu()

    def is_available(self) -> bool:
        return self.backend != GPUBackend.NONE

    def batch_hashaxe(
        self,
        pk,
        candidates: list[str],
        found_event,
    ) -> str | None:
        """
        Test a batch of passphrase candidates.

        Routes to:
          • _batch_cuda()   if CUDA backend
          • _batch_opencl() if OpenCL backend
          • _batch_cpu()    if no GPU (numpy SIMD fallback)

        Returns the matching passphrase string or None.
        """
        if self.backend == GPUBackend.CUDA:
            return self._batch_cuda(pk, candidates, found_event)
        if self.backend == GPUBackend.OPENCL:
            return self._batch_opencl(pk, candidates, found_event)
        return self._batch_cpu(pk, candidates, found_event)

    def _batch_cuda(self, pk, candidates, found_event) -> str | None:
        if getattr(self, "_using_libhashaxe", False):
            return self._batch_libhashaxe(pk, candidates, found_event)
        """NVIDIA CUDA batch — calls pre-compiled PTX kernel."""
        import numpy as np
        import pycuda.driver as drv

        max_pw = max(len(c.encode()) for c in candidates) + 1
        n      = len(candidates)

        # Build flat password buffer
        pw_flat  = np.zeros((n, max_pw), dtype=np.uint8)
        pw_lens  = np.zeros(n, dtype=np.int32)
        for i, c in enumerate(candidates):
            b = c.encode("utf-8", "replace")
            pw_flat[i, :len(b)] = list(b)
            pw_lens[i] = len(b)

        results = np.zeros(n, dtype=np.uint8)

        # Prepare GPU buffers
        pw_gpu   = drv.to_device(pw_flat.flatten())
        lens_gpu = drv.to_device(pw_lens)
        salt_gpu = drv.to_device(np.frombuffer(pk.salt, dtype=np.uint8))
        edata_gpu= drv.to_device(np.frombuffer(pk.edata[:16], dtype=np.uint8))
        res_gpu  = drv.to_device(results)

        # Launch kernel
        block = 256
        grid  = (n + block - 1) // block
        self._cuda_fn(
            pw_gpu, lens_gpu, np.int32(max_pw), np.int32(n),
            salt_gpu, np.int32(len(pk.salt)), np.int32(pk.rounds),
            np.int32(pk.key_len), np.int32(pk.iv_len),
            edata_gpu, np.int32(16), np.int32(0),
            res_gpu,
            block=(block, 1, 1), grid=(grid, 1),
        )
        results = drv.from_device(res_gpu, (n,), np.uint8)

        for i, match in enumerate(results):
            if match:
                return candidates[i]
        return None

    def _batch_libhashaxe(self, pk, candidates, found_event) -> str | None:
        """NVIDIA CUDA batch — calls C++ libhashaxe_engine.so using pinned memory."""
        n = len(candidates)
        if n > self._max_batch:
            n = self._max_batch
            
        buf_idx = 0 
        
        pw_flat_ptr = self._lib.engine_get_pw_flat(self._engine_ctx, buf_idx)
        pw_lens_ptr = self._lib.engine_get_pw_lens(self._engine_ctx, buf_idx)
        results_ptr = self._lib.engine_get_results(self._engine_ctx, buf_idx)
        
        FlatType = ctypes.c_uint8 * (n * self._max_pw)
        LensType = ctypes.c_int * n
        
        pw_flat = ctypes.cast(pw_flat_ptr, ctypes.POINTER(FlatType)).contents
        pw_lens = ctypes.cast(pw_lens_ptr, ctypes.POINTER(LensType)).contents
        
        offset = 0
        for i, c in enumerate(candidates[:n]):
            b = c.encode("utf-8", "replace")
            L = min(len(b), self._max_pw)
            pw_lens[i] = L
            for j in range(L):
                pw_flat[offset + j] = b[j]
            offset += self._max_pw
            
        salt_bytes = pk.salt
        edata_bytes = pk.edata[:16]
        
        self._lib.engine_launch(
            self._engine_ctx, buf_idx, n,
            salt_bytes, len(salt_bytes), pk.rounds,
            pk.key_len, pk.iv_len,
            edata_bytes, len(edata_bytes)
        )
        
        self._lib.engine_sync(self._engine_ctx, buf_idx)
        
        ResType = ctypes.c_uint8 * n
        results = ctypes.cast(results_ptr, ctypes.POINTER(ResType)).contents
        
        for i in range(n):
            if results[i]:
                return candidates[i]
        return None

    def _batch_opencl(self, pk, candidates, found_event) -> str | None:
        """OpenCL batch — calls compiled .cl kernel."""
        import numpy as np
        import pyopencl as cl

        max_pw = max(len(c.encode()) for c in candidates) + 1
        n      = len(candidates)

        pw_flat = np.zeros((n, max_pw), dtype=np.uint8)
        pw_lens = np.zeros(n, dtype=np.int32)
        for i, c in enumerate(candidates):
            b = c.encode("utf-8", "replace")
            pw_flat[i, :len(b)] = list(b)
            pw_lens[i] = len(b)

        mf = cl.mem_flags
        pw_buf   = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pw_flat.flatten())
        lens_buf = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pw_lens)
        salt_arr = np.frombuffer(pk.salt, dtype=np.uint8)
        salt_buf = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=salt_arr)
        edata_arr= np.frombuffer(pk.edata[:16], dtype=np.uint8)
        edata_buf= cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=edata_arr)
        results  = np.zeros(n, dtype=np.uint8)
        res_buf  = cl.Buffer(self._ctx, mf.WRITE_ONLY, results.nbytes)

        evt = self._prog.hashaxe_bcrypt_checkints(
            self._queue, (n,), None,
            pw_buf, lens_buf, np.int32(max_pw), np.int32(n),
            salt_buf, np.int32(len(pk.salt)), np.int32(pk.rounds),
            np.int32(pk.key_len), np.int32(pk.iv_len),
            edata_buf, np.int32(len(pk.edata[:16])), np.int32(0),
            res_buf,
        )
        evt.wait()
        cl.enqueue_copy(self._queue, results, res_buf).wait()

        for i, match in enumerate(results):
            if match:
                return candidates[i]
        return None

    def _batch_cpu(self, pk, candidates, found_event) -> str | None:
        """
        CPU SIMD fallback using numpy-vectorised bcrypt derivation.
        Delegates to cpu/simd.py for actual implementation.
        """
        from hashaxe.cpu.simd import simd_batch_hashaxe
        return simd_batch_hashaxe(pk, candidates, found_event)


# ── GPU info display ──────────────────────────────────────────────────────────

def gpu_info_string(device: GPUDevice | None) -> str:
    if device is None:
        return "No GPU detected — using CPU multiprocessing"
    speed_info = (
        f"{device.est_speed_pw_s:,.0f} pw/s (measured)"
        if device.est_speed_pw_s > 0
        else "Run --benchmark for actual speed"
    )
    return (
        f"{device.backend.name}: {device.name}  "
        f"({device.global_mem_mb} MB VRAM, {speed_info})"
    )


# ── Hardware Profiler & Multi-GPU ──────────────────────────────────────────────

class HardwareProfiler:
    """Auto-profiles system hardware to determine optimal dispatch strategies."""

    @staticmethod
    def auto_profile(device: GPUDevice | None = None) -> dict[str, Any]:
        """Run quick benchmarks to establish baseline capability."""
        dev = device or detect_gpu()
        cpu_cores = os.cpu_count() or 1
        
        profile = {
            "cpu_cores": cpu_cores,
            "has_gpu": dev is not None,
            "gpu_name": dev.name if dev else None,
            "gpu_backend": dev.backend.name if dev else None,
            "gpu_vram": dev.global_mem_mb if dev else 0,
            "recommended_workers": cpu_cores,
            "fast_hash_target": "gpu" if dev else "cpu",
            "slow_hash_target": "cpu"  # bcrypt remains CPU bound for orchestrator
        }
        
        # Adjust worker count based on RAM/CPU balance
        if dev and dev.backend == GPUBackend.CUDA:
            profile["recommended_workers"] = min(cpu_cores, 16) # Don't oversubscribe CUDA context
            
        return profile


class MultiGPUManager:
    """Manages distribution of workload across multiple CUDA devices."""
    
    def __init__(self):
        self.devices = []
        self._init_devices()

    def _init_devices(self):
        try:
            import pycuda.driver as drv
            drv.init()
            count = drv.Device.count()
            for i in range(count):
                dev = drv.Device(i)
                self.devices.append({
                    "id": i,
                    "name": dev.name(),
                    "memory": dev.total_memory() // (1024 * 1024)
                })
        except Exception:
            pass
            
    def get_device_count(self) -> int:
        return len(self.devices)
        
    def dispatch_kernel(self, kernel_fn, num_candidates: int, *args):
        """Distribute candidates equally among available GPUs.

        .. note::
            Multi-GPU distribution is not yet implemented.
            Currently, all GPU work is dispatched to device 0 via the
            single-context ``GPUCracker`` class. This method will be
            implemented when async multi-stream PTX dispatch is added.

        Raises:
            NotImplementedError: Always — callers should use ``GPUCracker.batch_hashaxe()``
                for single-GPU dispatch until multi-GPU support lands.
        """
        if not self.devices:
            return False

        raise NotImplementedError(
            f"Multi-GPU dispatch across {len(self.devices)} device(s) is not yet implemented. "
            "Use GPUCracker.batch_hashaxe() for single-GPU dispatch."
        )
