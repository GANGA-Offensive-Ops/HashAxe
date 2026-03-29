# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/osint/__init__.py
#  OSINT-powered personal dictionary generation from unstructured text sources.
#  Uses NLP-based profiling to generate target-specific password candidates.
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
hashaxe.osint — OSINT-powered personal dictionary generation.

This package provides NLP-based intelligence profiling to auto-generate
highly-probable, target-specific password candidate lists from
unstructured text sources (social media posts, bios, emails, etc.).

Modules:
  profiler        — Main OsintProfiler orchestrator
  nlp_engine      — Named Entity Recognition + keyword extraction
  keyword_mutator — Transforms extracted keywords into password candidates

Architecture:
  ┌──────────────┐
  │ Raw text     │  (tweets, bios, documents, URLs)
  │ or file path │
  └──────┬───────┘
         │
  ┌──────▼───────┐
  │  NLP Engine  │  NER, tokenization, frequency analysis
  └──────┬───────┘
         │
  ┌──────▼───────────┐
  │ Keyword Mutator  │  Leet, suffixes, date combos, initialism
  └──────┬───────────┘
         │
  ┌──────▼───────┐
  │  Candidates  │  → fed to main hashaxe() pipeline or exported
  └──────────────┘

GANGA Offensive Ops · Hashaxe V1
"""
from __future__ import annotations

from hashaxe.osint.profiler import OsintProfiler

__all__ = ["OsintProfiler"]
