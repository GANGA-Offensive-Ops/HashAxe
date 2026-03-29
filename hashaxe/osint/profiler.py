# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/osint/profiler.py
#  Main OSINT profiling orchestrator for targeted wordlist generation.
#  Accepts text/files/URLs, extracts keywords, mutates, and exports candidates.
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
osint/profiler.py — Main OSINT profiling orchestrator.

Provides the top-level ``OsintProfiler`` class that:
  1. Accepts raw text, file paths, or URLs as input
  2. Runs the NLP engine to extract keywords
  3. Passes keywords through the mutation pipeline
  4. Yields password candidates or exports a wordlist file

Usage:
  from hashaxe.osint import OsintProfiler

  profiler = OsintProfiler()
  profiler.load_file("target_tweets.txt")
  profiler.load_text("John Smith born 1990 loves Python and guitars")

  # Stream candidates directly
  for candidate in profiler.generate():
      print(candidate)

  # Or export to file
  profiler.export("target_wordlist.txt")
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

from hashaxe.osint.keyword_mutator import KeywordMutator
from hashaxe.osint.nlp_engine import ExtractedProfile, NLPEngine

logger = logging.getLogger(__name__)


class OsintProfiler:
    """Orchestrate OSINT-based password candidate generation.

    This is the main entry point for OSINT intelligence work. It:
      - Accumulates raw text from multiple sources
      - Runs NLP extraction once across all accumulated text
      - Generates password candidates via the mutation pipeline

    Thread-safe for read operations after ``extract()`` is called.
    """

    def __init__(
        self,
        min_length: int = 4,
        max_length: int = 64,
        use_spacy: bool = True,
    ):
        self._nlp_engine = NLPEngine(use_spacy=use_spacy)
        self._mutator = KeywordMutator(
            max_length=max_length,
            min_length=min_length,
        )
        self._raw_texts: list[str] = []
        self._profile: ExtractedProfile | None = None
        self._extracted = False

    @property
    def has_spacy(self) -> bool:
        """Whether spaCy NER is available."""
        return self._nlp_engine.has_spacy

    @property
    def profile(self) -> ExtractedProfile | None:
        """Return the extracted profile (None if not yet extracted)."""
        return self._profile

    def load_text(self, text: str) -> None:
        """Add raw text to the profiling buffer."""
        if text and text.strip():
            self._raw_texts.append(text)
            self._extracted = False
            logger.debug("Added %d chars of raw text", len(text))

    def load_file(self, path: str | Path) -> None:
        """Load text from a file path."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"OSINT source file not found: {path}")
        text = p.read_text(encoding="utf-8", errors="replace")
        self.load_text(text)
        logger.info("Loaded OSINT source: %s (%d bytes)", path, len(text))

    def load_stream(self, stream: TextIO) -> None:
        """Load text from a file-like stream (stdin, etc.)."""
        text = stream.read()
        self.load_text(text)

    def extract(self) -> ExtractedProfile:
        """Run NLP extraction on all accumulated text.

        Returns the ExtractionProfile with all identified tokens.
        Caches the result — call again after ``load_text()`` to re-extract.
        """
        if self._extracted and self._profile is not None:
            return self._profile

        combined = "\n\n".join(self._raw_texts)
        if not combined.strip():
            logger.warning("No text loaded for OSINT extraction")
            self._profile = ExtractedProfile()
            self._extracted = True
            return self._profile

        self._profile = self._nlp_engine.extract(combined)
        self._extracted = True

        summary = self._profile.summary()
        logger.info(
            "OSINT profile extracted: %d total tokens "
            "(%d names, %d emails, %d keywords, %d dates)",
            summary["total_tokens"],
            summary["names"],
            summary["emails"],
            summary["keywords"],
            summary["dates"],
        )
        return self._profile

    def generate(self) -> Iterator[str]:
        """Generate password candidates from the OSINT profile.

        Automatically calls ``extract()`` if not yet done.
        Yields one candidate at a time — memory efficient.
        """
        profile = self.extract()
        yield from self._mutator.mutate_profile(profile)

    def estimate_candidates(self) -> int:
        """Estimate the number of candidates that will be generated."""
        profile = self.extract()
        return self._mutator.estimate_candidates(profile)

    def export(self, output_path: str | Path, max_candidates: int = 0) -> int:
        """Export generated candidates to a wordlist file.

        Args:
            output_path: Path to write the wordlist.
            max_candidates: Maximum candidates to export (0 = unlimited).

        Returns:
            Number of candidates written.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        count = 0
        with out.open("w", encoding="utf-8") as f:
            for candidate in self.generate():
                f.write(candidate + "\n")
                count += 1
                if max_candidates and count >= max_candidates:
                    break

        logger.info(
            "OSINT wordlist exported: %d candidates → %s",
            count,
            output_path,
        )
        return count

    def info(self) -> dict:
        """Return profiler status information."""
        profile = self._profile
        return {
            "spacy": "Yes" if self.has_spacy else "No (regex-only mode)",
            "sources_loaded": len(self._raw_texts),
            "total_chars": sum(len(t) for t in self._raw_texts),
            "extracted": self._extracted,
            "tokens": profile.summary() if profile else {},
            "estimated_candidates": (self._mutator.estimate_candidates(profile) if profile else 0),
        }
