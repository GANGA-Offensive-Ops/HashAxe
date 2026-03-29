# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/gpu/__init__.py
#  GPU acceleration layer with CUDA (NVIDIA) and OpenCL (AMD/Intel) backends.
#  Auto-detects best available GPU at runtime for batch hash cracking.
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
gpu/ — GPU acceleration layer for hashaxe v2.

Backends (auto-detected at runtime, best available wins):
  1. CUDA    (NVIDIA RTX/Tesla — requires pycuda + CUDA toolkit)
  2. OpenCL  (NVIDIA/AMD/Intel — requires pyopencl)
  3. None    → falls back to cpu/simd.py numpy batching

Usage:
    from hashaxe.gpu.accelerator import GPUCracker, detect_gpu
    device  = detect_gpu()
    cracker = GPUCracker(device)
    result  = cracker.batch_hashaxe(pk, candidates, found_event)
"""

from hashaxe.gpu.accelerator import GPUBackend, GPUCracker, GPUDevice, detect_gpu, gpu_info_string

__all__ = ["GPUBackend", "GPUCracker", "GPUDevice", "detect_gpu", "gpu_info_string"]
