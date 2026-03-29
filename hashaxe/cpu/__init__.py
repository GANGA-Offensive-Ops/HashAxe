# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/cpu/__init__.py
#  CPU acceleration layer with NumPy vectorised batch AES and breach-frequency ordering.
#  Provides SIMD batching and smart wordlist ordering for non-GPU cracking.
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
cpu/ — CPU acceleration layer for hashaxe v2.

Modules:
  simd.py     — NumPy vectorised batch AES checkints + ctypes AES-NI
  wordfreq.py — Breach-frequency smart candidate ordering

Both modules are imported lazily by cracker.py and only activated
when use_smart_order=True or use_gpu=False respectively.
"""

from hashaxe.cpu.simd import benchmark_simd, get_optimal_batch_size, simd_batch_hashaxe
from hashaxe.cpu.wordfreq import FrequencyIndex, priority_candidates, smart_sort, top_k_first

__all__ = [
    "FrequencyIndex",
    "benchmark_simd",
    "get_optimal_batch_size",
    "priority_candidates",
    "simd_batch_hashaxe",
    "smart_sort",
    "top_k_first",
]
