# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/attacks/osint.py
#  OSINT attack mode — Intelligence-profiled candidate generation from target data.
#  Extracts keywords from social media/docs and generates mutated password candidates.
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
OSINT attack mode — Intelligence-profiled candidate generation.

Uses OSINT profiling to extract security-relevant keywords from
unstructured text (social media, bios, documents) and generate
highly-probable password candidates through intelligent mutation.

This attack mode integrates with the hashaxe AttackRegistry
and can be selected via: hashaxe --attack osint --osint-file target.txt

Dependencies:
  - Built-in: regex NER + frequency analysis (always available)
  - Optional: ``spacy`` for advanced Named Entity Recognition
"""
from __future__ import annotations

import logging
from collections.abc import Iterator

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack

log = logging.getLogger(__name__)

# Extended config field — we store OSINT source path in the wordlist field
# for compatibility, or users can use --osint-file via CLI


class OsintAttack(BaseAttack):
    """OSINT-powered candidate generation using NLP profiling.

    Accepts a text file containing target intelligence data (tweets,
    blog posts, social media bios, emails, etc.) and generates
    personalised password candidates through multi-stage mutation.

    The source file path is passed via the ``wordlist`` config field
    (or via ``--osint-file`` in the CLI).
    """

    attack_id = "osint"
    attack_name = "OSINT Profiler Attack"
    description = (
        "NLP-powered personal dictionary generation from OSINT text sources. "
        "Extracts names, dates, emails, keywords and generates targeted candidates."
    )

    def generate(self, config: AttackConfig) -> Iterator[str]:
        """Generate candidates from OSINT profile data."""
        from hashaxe.osint.profiler import OsintProfiler

        profiler = OsintProfiler(
            min_length=config.min_length,
            max_length=config.max_length,
        )

        # Load the OSINT source file (passed via wordlist field)
        if config.wordlist:
            try:
                profiler.load_file(config.wordlist)
                log.info("OSINT source loaded: %s", config.wordlist)
            except FileNotFoundError:
                log.error("OSINT source file not found: %s", config.wordlist)
                return

        # If a second wordlist is given, load it too
        if config.wordlist2:
            try:
                profiler.load_file(config.wordlist2)
                log.info("Additional OSINT source: %s", config.wordlist2)
            except FileNotFoundError:
                log.warning("Secondary OSINT source not found: %s", config.wordlist2)

        profile = profiler.extract()
        summary = profile.summary()
        log.info(
            "OSINT profile: %d tokens extracted "
            "(%d names, %d emails, %d keywords, %d dates, %d locations)",
            summary["total_tokens"],
            summary["names"],
            summary["emails"],
            summary["keywords"],
            summary["dates"],
            summary["locations"],
        )

        spacy_status = "spaCy NER" if profiler.has_spacy else "regex-only"
        log.info("NLP mode: %s", spacy_status)

        yield from profiler.generate()

    def estimate_keyspace(self, config: AttackConfig) -> int:
        """Estimate candidate count based on source file size."""
        if not config.wordlist:
            return 0
        try:
            from hashaxe.osint.profiler import OsintProfiler

            profiler = OsintProfiler()
            profiler.load_file(config.wordlist)
            return profiler.estimate_candidates()
        except Exception:
            return 5000  # Conservative default

    def validate_config(self, config: AttackConfig) -> str | None:
        """Validate that an OSINT source file is provided."""
        if not config.wordlist:
            return (
                "OSINT attack requires a text source file. "
                "Use --wordlist / -w to specify the OSINT intelligence file "
                "(e.g. target tweets, social media dump, bio text)"
            )
        return None


# Auto-register with the attack system
_registry = AttackRegistry()
_registry.register(OsintAttack())
