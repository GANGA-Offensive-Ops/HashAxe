# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_osint.py
#  Comprehensive tests for OSINT intelligence layer covering NLP engine and profiler.
#  Tests keyword extraction, mutator stages, attack plugin, and edge cases.
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
tests/test_osint.py — Comprehensive tests for OSINT Intelligence Layer.

Tests:
  - NLP Engine regex extraction (emails, dates, usernames, etc.)
  - NLP Engine keyword frequency analysis
  - Keyword Mutator candidate generation (all 12 stages)
  - OSINT Profiler orchestration (load, extract, generate, export)
  - OSINT Attack Plugin registration and generation
  - Edge cases: empty text, Unicode, very long text

GANGA Offensive Ops · Crack V1
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# NLP Engine Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestNLPEngine:
    """Test suite for hashaxe.osint.nlp_engine.NLPEngine."""

    def test_extract_emails(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("Contact me at john.smith@example.com or admin@corp.io")
        assert "john.smith@example.com" in profile.emails
        assert "admin@corp.io" in profile.emails

    def test_extract_usernames(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("Follow @darknight and @cyber_op on Twitter")
        assert "darknight" in profile.usernames
        assert "cyber_op" in profile.usernames

    def test_extract_hashtags(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("#hacking #cybersecurity #infosec")
        assert "hacking" in profile.hashtags
        assert "cybersecurity" in profile.hashtags
        assert "infosec" in profile.hashtags

    def test_extract_years(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("Born in 1990, graduated 2012, started work 2024")
        assert "1990" in profile.years
        assert "2012" in profile.years
        assert "2024" in profile.years

    def test_extract_dates(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("Birthday: 15/03/1990 Anniversary: 22-06-2015")
        assert any("1503" in d or "0315" in d for d in profile.dates)

    def test_extract_phones(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("Call me at 555-123-4567 or 9876543210")
        assert len(profile.phones) >= 1

    def test_extract_keywords_frequency(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        text = "python python python security hack hack code code code"
        profile = engine.extract(text)
        # 'python' and 'code' should be top keywords
        assert "python" in profile.keywords
        assert "code" in profile.keywords

    def test_stopwords_filtered(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("the and for are but not you all can")
        # Stopwords should not appear in keywords
        for sw in ["the", "and", "for", "are", "but", "not", "you", "all", "can"]:
            assert sw not in profile.keywords

    def test_email_local_part_extraction(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("email: john.smith@gmail.com")
        # Should extract "John" and/or "Smith" from email local part
        name_lower = [n.lower() for n in profile.names]
        assert "john" in name_lower or "smith" in name_lower

    def test_empty_text(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("")
        assert profile.all_tokens == []

    def test_unicode_text(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("Ünïcödé tëst 日本語 contact@test.com 2024")
        assert "contact@test.com" in profile.emails
        assert "2024" in profile.years

    def test_all_tokens_deduplicated(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("test test test python python @testuser")
        tokens = profile.all_tokens
        assert len(tokens) == len(set(t.lower() for t in tokens))

    def test_summary_dict(self):
        from hashaxe.osint.nlp_engine import NLPEngine

        engine = NLPEngine(use_spacy=False)
        profile = engine.extract("john@test.com loves @cybersec in 2024")
        summary = profile.summary()
        assert "total_tokens" in summary
        assert "emails" in summary
        assert summary["emails"] >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# Keyword Mutator Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestKeywordMutator:
    """Test suite for hashaxe.osint.keyword_mutator.KeywordMutator."""

    def _make_profile(self, **kwargs):
        from hashaxe.osint.nlp_engine import ExtractedProfile

        return ExtractedProfile(**kwargs)

    def test_case_variant_mutations(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(keywords=["dragon"])
        candidates = list(mutator.mutate_profile(profile))
        assert "dragon" in candidates
        assert "Dragon" in candidates
        assert "DRAGON" in candidates

    def test_year_suffix_mutations(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(keywords=["admin"], years=["1990"])
        candidates = list(mutator.mutate_profile(profile))
        assert "admin2024" in candidates
        assert "admin1990" in candidates

    def test_digit_suffix_mutations(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(keywords=["pass"])
        candidates = list(mutator.mutate_profile(profile))
        assert "pass123" in candidates
        assert "Pass1" in candidates

    def test_symbol_suffix_mutations(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(keywords=["test"])
        candidates = list(mutator.mutate_profile(profile))
        assert "test!" in candidates
        assert "Test@" in candidates

    def test_leet_speak_mutations(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(keywords=["password"])
        candidates = list(mutator.mutate_profile(profile))
        assert "p@$$w0rd" in candidates

    def test_name_combination_mutations(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(names=["John", "Smith"])
        candidates = list(mutator.mutate_profile(profile))
        assert "JohnSmith" in candidates or "johnsmith" in candidates

    def test_deduplication(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(keywords=["test"])
        candidates = list(mutator.mutate_profile(profile))
        assert len(candidates) == len(set(candidates))

    def test_min_length_filter(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=6)
        profile = self._make_profile(keywords=["ab", "longword"])
        candidates = list(mutator.mutate_profile(profile))
        for c in candidates:
            assert len(c) >= 6

    def test_max_length_filter(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(max_length=10)
        profile = self._make_profile(keywords=["short"])
        candidates = list(mutator.mutate_profile(profile))
        for c in candidates:
            assert len(c) <= 10

    def test_email_based_mutations(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator(min_length=1)
        profile = self._make_profile(emails=["john.doe@gmail.com"])
        candidates = list(mutator.mutate_profile(profile))
        assert "john.doe" in candidates
        assert "john.doe!" in candidates

    def test_estimate_candidates(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator()
        profile = self._make_profile(keywords=["test", "admin"], names=["John"])
        est = mutator.estimate_candidates(profile)
        assert est > 0

    def test_empty_profile(self):
        from hashaxe.osint.keyword_mutator import KeywordMutator

        mutator = KeywordMutator()
        profile = self._make_profile()
        candidates = list(mutator.mutate_profile(profile))
        assert candidates == []


# ═══════════════════════════════════════════════════════════════════════════════
# OSINT Profiler Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestOsintProfiler:
    """Test suite for hashaxe.osint.profiler.OsintProfiler."""

    def test_load_text_and_generate(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(min_length=1, use_spacy=False)
        profiler.load_text("John Smith born 1990 loves python and guitars admin@corp.com")
        candidates = list(profiler.generate())
        assert len(candidates) > 0
        assert any("john" in c.lower() for c in candidates)

    def test_load_file(self):
        from hashaxe.osint import OsintProfiler

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Target intel: Alice Johnson works at TechCorp since 2020 alice.j@techcorp.com")
            f.flush()
            path = f.name

        try:
            profiler = OsintProfiler(use_spacy=False)
            profiler.load_file(path)
            profile = profiler.extract()
            assert "alice.j@techcorp.com" in profile.emails
            assert profile.summary()["total_tokens"] > 0
        finally:
            os.unlink(path)

    def test_load_file_not_found(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(use_spacy=False)
        with pytest.raises(FileNotFoundError):
            profiler.load_file("/nonexistent/path/fake.txt")

    def test_export_wordlist(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(min_length=1, use_spacy=False)
        profiler.load_text("admin dragon monkey shadow 2024")

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            out_path = f.name

        try:
            count = profiler.export(out_path)
            assert count > 0
            content = Path(out_path).read_text()
            lines = [l for l in content.strip().split("\n") if l]
            assert len(lines) == count
        finally:
            os.unlink(out_path)

    def test_export_max_candidates(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(min_length=1, use_spacy=False)
        profiler.load_text("admin dragon monkey shadow password 2024 2025 security")

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            out_path = f.name

        try:
            count = profiler.export(out_path, max_candidates=10)
            assert count == 10
        finally:
            os.unlink(out_path)

    def test_estimate_candidates(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(use_spacy=False)
        profiler.load_text("test admin password")
        est = profiler.estimate_candidates()
        assert est > 0

    def test_info_dict(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(use_spacy=False)
        profiler.load_text("test data")
        info = profiler.info()
        assert "sources_loaded" in info
        assert info["sources_loaded"] == 1

    def test_empty_input(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(use_spacy=False)
        profiler.load_text("")
        candidates = list(profiler.generate())
        assert candidates == []

    def test_multiple_sources(self):
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(min_length=1, use_spacy=False)
        profiler.load_text("Source 1: john@example.com born 1985")
        profiler.load_text("Source 2: works at CyberCorp loves hacking")
        profile = profiler.extract()
        assert profile.summary()["total_tokens"] > 0
        assert "john@example.com" in profile.emails


# ═══════════════════════════════════════════════════════════════════════════════
# OSINT Attack Plugin Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestOsintAttackPlugin:
    """Test that the OSINT attack plugin integrates with AttackRegistry."""

    def test_plugin_registered(self):
        from hashaxe.attacks import AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        assert "osint" in registry

    def test_plugin_metadata(self):
        from hashaxe.attacks import AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        plugin = registry.get("osint")
        assert plugin is not None
        assert plugin.attack_id == "osint"
        assert plugin.attack_name == "OSINT Profiler Attack"
        assert "NLP" in plugin.description

    def test_plugin_validate_no_wordlist(self):
        from hashaxe.attacks import AttackConfig, AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        plugin = registry.get("osint")
        config = AttackConfig()
        err = plugin.validate_config(config)
        assert err is not None
        assert "source file" in err.lower() or "osint" in err.lower()

    def test_plugin_generate_with_file(self):
        from hashaxe.attacks import AttackConfig, AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        plugin = registry.get("osint")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Bob Wilson loves basketball 2024 bob.w@gmail.com @bobwilson")
            path = f.name

        try:
            config = AttackConfig(wordlist=path, min_length=1)
            candidates = list(plugin.generate(config))
            assert len(candidates) > 0
            assert any("bob" in c.lower() for c in candidates)
        finally:
            os.unlink(path)

    def test_plugin_estimate_keyspace(self):
        from hashaxe.attacks import AttackConfig, AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        plugin = registry.get("osint")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test data admin password")
            path = f.name

        try:
            config = AttackConfig(wordlist=path)
            est = plugin.estimate_keyspace(config)
            assert est > 0
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# Integration / Edge Case Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestOsintIntegration:
    """End-to-end integration tests for the OSINT pipeline."""

    def test_full_pipeline_realistic(self):
        """Test with realistic social media-style text."""
        from hashaxe.osint import OsintProfiler

        text = """
        Hey everyone! I'm Sarah Connor, 28, from Los Angeles.
        Love my dog Max and my cat Whiskers!
        Birthday: 15/08/1997
        Just graduated from UCLA in 2020.
        Work at Cyberdyne Systems as a security engineer.
        Email: sarah.connor@cyberdyne.com
        Follow me @sarahc97
        #cybersecurity #infosec #hacking
        My favorite password... just kidding! But I love Terminator1984
        """

        profiler = OsintProfiler(min_length=1, use_spacy=False)
        profiler.load_text(text)
        candidates = list(profiler.generate())

        # Should extract and mutate key tokens
        assert len(candidates) > 50
        lower_candidates = {c.lower() for c in candidates}
        # Check for expected patterns
        assert any("sarah" in c for c in lower_candidates)
        assert any("1997" in c for c in lower_candidates)
        assert any("cyberdyne" in c for c in lower_candidates)
        assert any("sarahc97" in c for c in lower_candidates)

    def test_large_text_performance(self):
        """Ensure the engine handles large text without memory issues."""
        from hashaxe.osint import OsintProfiler

        # Generate a large text
        large_text = "security hacking python " * 5000
        large_text += "admin@test.com 2024 @hackerman"

        profiler = OsintProfiler(use_spacy=False)
        profiler.load_text(large_text)
        profile = profiler.extract()
        assert profile.summary()["total_tokens"] > 0

    def test_candidate_uniqueness(self):
        """All generated candidates must be unique."""
        from hashaxe.osint import OsintProfiler

        profiler = OsintProfiler(min_length=1, use_spacy=False)
        profiler.load_text("admin password dragon monkey shadow qwerty")
        candidates = list(profiler.generate())
        assert len(candidates) == len(set(candidates))
