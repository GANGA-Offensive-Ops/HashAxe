# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_pcfg_ai.py
#  Tests for PCFG grammar attack and adaptive AI controller.
#  Covers tokenizer, model training, generation, and temperature feedback loop.
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
tests/test_pcfg_ai.py — Tests for PCFG Grammar Attack and Adaptive AI Controller.

Tests:
  - PCFG tokenizer and structure extraction
  - PCFG model training and generation
  - PCFG attack plugin registration and end-to-end
  - Adaptive AI temperature controller feedback loop
  - Edge cases: empty wordlists, single words, unicode

GANGA Offensive Ops · Crack V1
"""
from __future__ import annotations

import os
import tempfile

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# PCFG Tokenizer Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPCFGTokenizer:
    """Test the PCFG tokenization and structure extraction."""

    def test_simple_word(self):
        from hashaxe.attacks.pcfg import _structure_key, _tokenize

        tokens = _tokenize("password")
        assert len(tokens) > 0
        key = _structure_key(tokens)
        assert key == "L8"  # 8 lowercase letters

    def test_mixed_case_digits(self):
        from hashaxe.attacks.pcfg import _structure_key, _tokenize

        tokens = _tokenize("Admin123")
        key = _structure_key(tokens)
        assert "U" in key  # Has uppercase
        assert "L" in key  # Has lowercase
        assert "D" in key  # Has digits

    def test_with_symbols(self):
        from hashaxe.attacks.pcfg import _structure_key, _tokenize

        tokens = _tokenize("pass!@#")
        key = _structure_key(tokens)
        assert "S" in key  # Has symbols

    def test_digits_only(self):
        from hashaxe.attacks.pcfg import _structure_key, _tokenize

        tokens = _tokenize("123456")
        key = _structure_key(tokens)
        assert key == "D6"

    def test_complex_password(self):
        from hashaxe.attacks.pcfg import _structure_key, _tokenize

        tokens = _tokenize("Password123!")
        key = _structure_key(tokens)
        # P=U1, assword=L7, 123=D3, !=S1
        assert key == "U1L7D3S1"

    def test_empty_string(self):
        from hashaxe.attacks.pcfg import _tokenize

        tokens = _tokenize("")
        assert tokens == []


# ═══════════════════════════════════════════════════════════════════════════════
# PCFG Model Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPCFGModel:
    """Test PCFG model training and generation."""

    def _make_wordlist(self, words: list[str]) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        for w in words:
            f.write(w + "\n")
        f.close()
        return f.name

    def test_train_basic(self):
        from hashaxe.attacks.pcfg import PCFGModel

        path = self._make_wordlist(
            [
                "password",
                "password1",
                "admin123",
                "letmein",
                "dragon",
            ]
        )
        try:
            model = PCFGModel()
            count = model.train(path)
            assert count == 5
            assert len(model.structure_counts) > 0
        finally:
            os.unlink(path)

    def test_train_empty_wordlist(self):
        from hashaxe.attacks.pcfg import PCFGModel

        path = self._make_wordlist([])
        try:
            model = PCFGModel()
            count = model.train(path)
            assert count == 0
        finally:
            os.unlink(path)

    def test_generate_produces_candidates(self):
        from hashaxe.attacks.pcfg import PCFGModel

        path = self._make_wordlist(
            [
                "password",
                "admin",
                "letmein",
                "dragon",
                "monkey",
                "shadow",
                "master",
                "qwerty",
                "welcome",
                "hello",
            ]
        )
        try:
            model = PCFGModel()
            model.train(path)
            candidates = list(model.generate(max_length=64))
            assert len(candidates) > 0
        finally:
            os.unlink(path)

    def test_generate_respects_length_bounds(self):
        from hashaxe.attacks.pcfg import PCFGModel

        path = self._make_wordlist(
            [
                "ab",
                "abc",
                "abcdef",
                "abcdefghij",
                "pass123",
            ]
        )
        try:
            model = PCFGModel()
            model.train(path)
            candidates = list(model.generate(min_length=4, max_length=8))
            for c in candidates:
                assert 4 <= len(c) <= 8
        finally:
            os.unlink(path)

    def test_stats(self):
        from hashaxe.attacks.pcfg import PCFGModel

        path = self._make_wordlist(["password1", "admin123", "test!"])
        try:
            model = PCFGModel()
            model.train(path)
            stats = model.stats
            assert stats["words_trained"] == 3
            assert stats["unique_structures"] > 0
            assert len(stats["top_5_structures"]) > 0
        finally:
            os.unlink(path)

    def test_structure_frequency_ordering(self):
        from hashaxe.attacks.pcfg import PCFGModel

        # Create wordlist where L8 structure appears most
        words = ["password", "baseball", "football", "superman", "batman12"]
        path = self._make_wordlist(words)
        try:
            model = PCFGModel()
            model.train(path)
            top = model.structure_counts.most_common(1)[0][0]
            assert top == "L8"  # 4 out of 5 are L8
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# PCFG Attack Plugin Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPCFGAttackPlugin:
    """Test PCFG attack plugin registration and integration."""

    def test_plugin_registered(self):
        from hashaxe.attacks import AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        assert "pcfg" in registry

    def test_plugin_metadata(self):
        from hashaxe.attacks import AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        plugin = registry.get("pcfg")
        assert plugin.attack_id == "pcfg"
        assert "Grammar" in plugin.attack_name

    def test_plugin_validate_no_wordlist(self):
        from hashaxe.attacks import AttackConfig, AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        plugin = registry.get("pcfg")
        err = plugin.validate_config(AttackConfig())
        assert err is not None

    def test_plugin_generate(self):
        import os
        import tempfile

        from hashaxe.attacks import AttackConfig, AttackRegistry

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for w in ["password", "password1", "admin123", "letmein!", "dragon99"]:
                f.write(w + "\n")
            path = f.name

        try:
            registry = AttackRegistry()
            registry.discover()
            plugin = registry.get("pcfg")
            config = AttackConfig(wordlist=path, min_length=1)
            candidates = list(plugin.generate(config))
            assert len(candidates) > 0
            # Should generate variants based on learned structures
            assert len(set(candidates)) == len(candidates)  # deduplicated
        finally:
            os.unlink(path)

    def test_plugin_estimate_keyspace(self):
        import os
        import tempfile

        from hashaxe.attacks import AttackConfig, AttackRegistry

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test\n" * 100)
            path = f.name

        try:
            registry = AttackRegistry()
            registry.discover()
            plugin = registry.get("pcfg")
            est = plugin.estimate_keyspace(AttackConfig(wordlist=path))
            assert est > 0
        finally:
            os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive AI Controller Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestAdaptiveAI:
    """Test the Adaptive AI temperature/sampling controller."""

    def test_initial_state(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig()
        assert config.temperature == 1.2
        assert config.top_k == 50
        assert config.hit_rate == 0.0

    def test_record_generated(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig()
        config.record_generated(100)
        assert config.candidates_generated == 100

    def test_record_match(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig()
        config.record_generated(100)
        config.record_match(5)
        assert config.candidates_matched == 5
        assert config.hit_rate == 0.05

    def test_should_adjust_interval(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig(adjustment_interval=100)
        config.record_generated(50)
        assert not config.should_adjust()
        config.record_generated(60)
        assert config.should_adjust()

    def test_adjust_exploit_on_high_hit_rate(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig(adjustment_interval=10)
        config.record_generated(100)
        config.record_match(5)  # 5% hit rate > 1%
        initial_temp = config.temperature
        changes = config.adjust()
        assert changes["action"] == "exploit"
        assert config.temperature < initial_temp

    def test_adjust_explore_on_low_hit_rate(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig(adjustment_interval=10)
        config.record_generated(2000)
        config.record_match(0)  # 0% hit rate
        initial_temp = config.temperature
        changes = config.adjust()
        assert changes["action"] == "explore"
        assert config.temperature > initial_temp

    def test_adjust_hold_on_moderate_rate(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig(adjustment_interval=10)
        config.record_generated(1000)
        config.record_match(5)  # 0.5% = between 0.1% and 1%
        changes = config.adjust()
        assert changes["action"] == "hold"

    def test_temperature_clamped_min(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig(temperature=0.61, temp_min=0.6, adjustment_interval=1)
        config.record_generated(100)
        config.record_match(50)  # 50% hit rate → exploit
        for _ in range(50):
            config.adjust()
        assert config.temperature >= config.temp_min

    def test_temperature_clamped_max(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig(temperature=1.95, temp_max=2.0, adjustment_interval=1)
        config.record_generated(5000)
        config.record_match(0)  # 0% → explore
        for _ in range(50):
            config.record_generated(500)
            config.adjust()
        assert config.temperature <= config.temp_max

    def test_snapshot(self):
        from hashaxe.ai.adaptive import AdaptiveConfig

        config = AdaptiveConfig()
        config.record_generated(100)
        config.record_match(3)
        snap = config.snapshot()
        assert "temperature" in snap
        assert "hit_rate" in snap
        assert snap["generated"] == 100
        assert snap["matched"] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Registry Integration
# ═══════════════════════════════════════════════════════════════════════════════


class TestAllAttacksRegistered:
    """Verify all V1 attack modes are discoverable."""

    def test_all_v4_attacks_present(self):
        from hashaxe.attacks import AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        ids = registry.list_ids()
        expected = [
            "wordlist",
            "mask",
            "combinator",
            "prince",
            "markov",
            "hybrid",
            "policy",
            "ai",
            "osint",
            "pcfg",
        ]
        for eid in expected:
            assert eid in ids, f"Attack '{eid}' not registered"

    def test_total_attack_count(self):
        from hashaxe.attacks import AttackRegistry

        registry = AttackRegistry()
        registry.discover()
        assert len(registry) >= 10
