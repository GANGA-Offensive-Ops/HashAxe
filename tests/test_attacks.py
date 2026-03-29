# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_attacks.py
#  Tests for advanced attack modes including wordlist, mask, combinator, PRINCE.
#  Covers BaseAttack contract, AttackRegistry, and keyspace estimation.
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
Tests for Batch 6: Advanced Attack Modes.

Coverage:
  - BaseAttack ABC contract
  - AttackRegistry auto-discovery
  - Wordlist attack: streaming, length filtering
  - Mask attack: ?l?u?d?s generation, keyspace estimation
  - Combinator attack: Cartesian product
  - PRINCE attack: element chaining
  - Markov attack: transition model, generation
  - Hybrid attack: word + mask suffix
  - Policy attack: constraint parsing, filtering
  - CLI argument parsing

GANGA Offensive Ops · Crack V3
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hashaxe.attacks import AttackConfig, AttackRegistry, BaseAttack


def _make_wordlist(words: list[str]) -> str:
    """Create a temporary wordlist file, return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    for w in words:
        f.write(w + "\n")
    f.close()
    return f.name


# ══════════════════════════════════════════════════════════════════════════════
# Registry Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAttackRegistry(unittest.TestCase):
    def test_all_attacks_registered(self):
        reg = AttackRegistry()
        reg.discover()
        expected = ["wordlist", "mask", "combinator", "prince", "markov", "hybrid", "policy"]
        for aid in expected:
            self.assertIn(aid, reg, f"{aid} not registered")

    def test_registry_count(self):
        reg = AttackRegistry()
        reg.discover()
        self.assertGreaterEqual(len(reg), 7)

    def test_list_ids(self):
        reg = AttackRegistry()
        ids = reg.list_ids()
        self.assertIn("wordlist", ids)
        self.assertIn("mask", ids)


# ══════════════════════════════════════════════════════════════════════════════
# Wordlist Attack Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestWordlistAttack(unittest.TestCase):
    def setUp(self):
        self._wl = _make_wordlist(["password", "test123", "admin", "root", ""])

    def tearDown(self):
        os.unlink(self._wl)

    def test_generate_all(self):
        from hashaxe.attacks.wordlist import WordlistAttack

        atk = WordlistAttack()
        config = AttackConfig(wordlist=self._wl)
        results = list(atk.generate(config))
        self.assertEqual(len(results), 4)  # empty line skipped
        self.assertIn("password", results)

    def test_length_filter(self):
        from hashaxe.attacks.wordlist import WordlistAttack

        atk = WordlistAttack()
        config = AttackConfig(wordlist=self._wl, min_length=5)
        results = list(atk.generate(config))
        self.assertNotIn("root", results)
        self.assertIn("password", results)

    def test_estimate_keyspace(self):
        from hashaxe.attacks.wordlist import WordlistAttack

        atk = WordlistAttack()
        config = AttackConfig(wordlist=self._wl)
        self.assertEqual(atk.estimate_keyspace(config), 4)

    def test_validate_no_wordlist(self):
        from hashaxe.attacks.wordlist import WordlistAttack

        atk = WordlistAttack()
        config = AttackConfig()
        self.assertIsNotNone(atk.validate_config(config))


# ══════════════════════════════════════════════════════════════════════════════
# Mask Attack Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestMaskAttack(unittest.TestCase):
    def test_generate_digits(self):
        from hashaxe.attacks.mask import MaskAttack

        atk = MaskAttack()
        config = AttackConfig(mask="?d?d")
        results = list(atk.generate(config))
        self.assertEqual(len(results), 100)  # 10 x 10
        self.assertIn("00", results)
        self.assertIn("99", results)

    def test_estimate_keyspace(self):
        from hashaxe.attacks.mask import MaskAttack

        atk = MaskAttack()
        config = AttackConfig(mask="?l?d?d")
        self.assertEqual(atk.estimate_keyspace(config), 26 * 10 * 10)

    def test_custom_charset(self):
        from hashaxe.attacks.mask import MaskAttack

        atk = MaskAttack()
        config = AttackConfig(mask="?1?1", custom_charsets={"?1": "ab"})
        results = list(atk.generate(config))
        self.assertEqual(len(results), 4)
        self.assertIn("aa", results)
        self.assertIn("ab", results)

    def test_validate_no_mask(self):
        from hashaxe.attacks.mask import MaskAttack

        atk = MaskAttack()
        self.assertIsNotNone(atk.validate_config(AttackConfig()))


# ══════════════════════════════════════════════════════════════════════════════
# Combinator Attack Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCombinatorAttack(unittest.TestCase):
    def setUp(self):
        self._wl1 = _make_wordlist(["pass", "admin"])
        self._wl2 = _make_wordlist(["123", "456"])

    def tearDown(self):
        os.unlink(self._wl1)
        os.unlink(self._wl2)

    def test_generate_cartesian(self):
        from hashaxe.attacks.combinator import CombinatorAttack

        atk = CombinatorAttack()
        config = AttackConfig(wordlist=self._wl1, wordlist2=self._wl2)
        results = list(atk.generate(config))
        self.assertEqual(len(results), 4)
        self.assertIn("pass123", results)
        self.assertIn("admin456", results)

    def test_estimate_keyspace(self):
        from hashaxe.attacks.combinator import CombinatorAttack

        atk = CombinatorAttack()
        config = AttackConfig(wordlist=self._wl1, wordlist2=self._wl2)
        self.assertEqual(atk.estimate_keyspace(config), 4)

    def test_validate_missing_wordlist2(self):
        from hashaxe.attacks.combinator import CombinatorAttack

        atk = CombinatorAttack()
        config = AttackConfig(wordlist=self._wl1)
        self.assertIsNotNone(atk.validate_config(config))


# ══════════════════════════════════════════════════════════════════════════════
# PRINCE Attack Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestPrinceAttack(unittest.TestCase):
    def setUp(self):
        self._wl = _make_wordlist(["ab", "cd"])

    def tearDown(self):
        os.unlink(self._wl)

    def test_single_element(self):
        from hashaxe.attacks.prince import PrinceAttack

        atk = PrinceAttack()
        config = AttackConfig(wordlist=self._wl, prince_min_elems=1, prince_max_elems=1)
        results = list(atk.generate(config))
        self.assertEqual(len(results), 2)
        self.assertIn("ab", results)

    def test_two_elements(self):
        from hashaxe.attacks.prince import PrinceAttack

        atk = PrinceAttack()
        config = AttackConfig(wordlist=self._wl, prince_min_elems=2, prince_max_elems=2)
        results = list(atk.generate(config))
        self.assertEqual(len(results), 4)  # ab+ab, ab+cd, cd+ab, cd+cd
        self.assertIn("abcd", results)
        self.assertIn("cdab", results)

    def test_estimate_keyspace(self):
        from hashaxe.attacks.prince import PrinceAttack

        atk = PrinceAttack()
        config = AttackConfig(wordlist=self._wl, prince_min_elems=1, prince_max_elems=2)
        # 2^1 + 2^2 = 6
        self.assertEqual(atk.estimate_keyspace(config), 6)


# ══════════════════════════════════════════════════════════════════════════════
# Markov Attack Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestMarkovAttack(unittest.TestCase):
    def setUp(self):
        self._wl = _make_wordlist(["abc", "abd", "xyz"])

    def tearDown(self):
        os.unlink(self._wl)

    def test_generates_candidates(self):
        from hashaxe.attacks.markov import MarkovAttack

        atk = MarkovAttack()
        config = AttackConfig(wordlist=self._wl, markov_order=2, max_length=5)
        results = list(atk.generate(config))
        self.assertGreater(len(results), 0)

    def test_contains_training_words(self):
        from hashaxe.attacks.markov import MarkovAttack

        atk = MarkovAttack()
        config = AttackConfig(wordlist=self._wl, markov_order=2, max_length=5)
        results = list(atk.generate(config))
        # Training words should be among the generated candidates
        self.assertIn("abc", results)


# ══════════════════════════════════════════════════════════════════════════════
# Hybrid Attack Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestHybridAttack(unittest.TestCase):
    def setUp(self):
        self._wl = _make_wordlist(["pass", "admin"])

    def tearDown(self):
        os.unlink(self._wl)

    def test_generate_hybrid(self):
        from hashaxe.attacks.hybrid import HybridAttack

        atk = HybridAttack()
        config = AttackConfig(wordlist=self._wl, mask="?d?d")
        results = list(atk.generate(config))
        self.assertEqual(len(results), 200)  # 2 words x 100 suffixes
        self.assertIn("pass00", results)
        self.assertIn("admin99", results)

    def test_estimate_keyspace(self):
        from hashaxe.attacks.hybrid import HybridAttack

        atk = HybridAttack()
        config = AttackConfig(wordlist=self._wl, mask="?d?d")
        self.assertEqual(atk.estimate_keyspace(config), 200)

    def test_validate_missing_mask(self):
        from hashaxe.attacks.hybrid import HybridAttack

        atk = HybridAttack()
        config = AttackConfig(wordlist=self._wl)
        self.assertIsNotNone(atk.validate_config(config))


# ══════════════════════════════════════════════════════════════════════════════
# Policy Attack Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestPolicyAttack(unittest.TestCase):
    def setUp(self):
        self._wl = _make_wordlist(
            [
                "Password1!",  # passes: len>=8, upper, digit, symbol
                "short",  # fails: too short, no upper/digit/symbol
                "nodigits!A",  # fails: no digit
                "Admin2024#",  # passes
            ]
        )

    def tearDown(self):
        os.unlink(self._wl)

    def test_filter_wordlist(self):
        from hashaxe.attacks.policy import PolicyAttack

        atk = PolicyAttack()
        config = AttackConfig(wordlist=self._wl, policy="len>=8,upper,digit,symbol")
        results = list(atk.generate(config))
        self.assertIn("Password1!", results)
        self.assertIn("Admin2024#", results)
        self.assertNotIn("short", results)

    def test_parse_policy(self):
        from hashaxe.attacks.policy import _parse_policy

        constraints = _parse_policy("len>=8,upper,digit,symbol,len<=16")
        self.assertEqual(constraints["min_length"], 8)
        self.assertEqual(constraints["max_length"], 16)
        self.assertTrue(constraints["require_upper"])
        self.assertTrue(constraints["require_digit"])
        self.assertTrue(constraints["require_symbol"])

    def test_check_policy(self):
        from hashaxe.attacks.policy import _check_policy

        constraints = {
            "min_length": 8,
            "max_length": 16,
            "require_upper": True,
            "require_lower": True,
            "require_digit": True,
            "require_symbol": True,
            "no_repeat": False,
        }
        self.assertTrue(_check_policy("Password1!", constraints))
        self.assertFalse(_check_policy("short", constraints))
        self.assertFalse(_check_policy("onlylowercase1!", constraints))

    def test_validate_no_policy(self):
        from hashaxe.attacks.policy import PolicyAttack

        atk = PolicyAttack()
        self.assertIsNotNone(atk.validate_config(AttackConfig()))


if __name__ == "__main__":
    unittest.main()
