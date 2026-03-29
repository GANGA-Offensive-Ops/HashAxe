# ==========================================================================================
# 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: tests/test_intelligence.py
#  Tests for intelligence features including classifier, recommender, MITRE mapper.
#  Covers hash classification, attack recommendations, and MITRE ATT&CK mapping.
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
Tests for Intelligence Features: Classifier, Recommender, MITRE Mapper.
"""
from __future__ import annotations

import pytest


class TestSmartClassifier:
    def test_classify_bcrypt(self):
        from hashaxe.identify.classifier import classify

        result = classify("$2b$12$VuqZfLz.GOuU7qDxKXxKNuJPjFdHTmoWnPiJfbNSPYUVqC3BoOiYe")
        assert result.format_id == "hash.bcrypt"
        assert result.confidence == 1.0
        assert result.hashcat_mode == 3200
        assert result.difficulty == "SLOW"
        assert "GPU" in result.estimated_speed

    def test_classify_kerberoast(self):
        from hashaxe.identify.classifier import classify

        h = "$krb5tgs$23$*user$REALM$test/spn*$aaaa1111bbbb2222cccc3333dddd4444$eeeeffff00001111"
        result = classify(h)
        assert result.format_id == "network.krb5tgs_rc4"
        assert result.hashcat_mode == 13100

    def test_classify_dcc2(self):
        from hashaxe.identify.classifier import classify

        result = classify("$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f")
        assert result.format_id == "network.dcc2"
        assert result.hashcat_mode == 2100

    def test_classify_unknown(self):
        from hashaxe.identify.classifier import classify

        result = classify("this_is_not_a_hash")
        assert result.format_id == "unknown"
        assert result.confidence == 0.0

    def test_classify_empty(self):
        from hashaxe.identify.classifier import classify

        result = classify("")
        assert result.format_id == "unknown"

    def test_classify_md5_raw(self):
        from hashaxe.identify.classifier import classify

        result = classify("5d41402abc4b2a76b9719d911017c592")
        assert result.format_id == "hash.md5"
        assert result.hashcat_mode == 0
        assert result.difficulty == "TRIVIAL"

    def test_classify_cisco_type8(self):
        from hashaxe.identify.classifier import classify

        result = classify("$8$dsYGNam6YVewYQi$hPHElm0gV8SHiTByOHFgS4AJwbSwphEQ/fNOjxCA8nY.")
        assert result.format_id == "network.cisco_type8"
        assert result.hashcat_mode == 9200

    def test_classify_ansible(self):
        from hashaxe.identify.classifier import classify

        result = classify("$ANSIBLE_VAULT;1.1;AES256")
        assert result.format_id == "token.ansible_vault"
        assert result.hashcat_mode == 16900

    def test_classify_has_recommendation(self):
        from hashaxe.identify.classifier import classify

        result = classify("$2b$12$VuqZfLz.GOuU7qDxKXxKNuJPjFdHTmoWnPiJfbNSPYUVqC3BoOiYe")
        assert result.attack_recommendation != ""

    def test_classify_john_format(self):
        from hashaxe.identify.classifier import classify

        result = classify("5d41402abc4b2a76b9719d911017c592")
        assert result.john_format == "Raw-MD5"

    def test_classify_batch(self):
        from hashaxe.identify.classifier import classify_batch

        results = classify_batch(
            [
                "5d41402abc4b2a76b9719d911017c592",
                "$2b$12$VuqZfLz.GOuU7qDxKXxKNuJPjFdHTmoWnPiJfbNSPYUVqC3BoOiYe",
            ]
        )
        assert len(results) == 2
        assert results[0].format_id == "hash.md5"
        assert results[1].format_id == "hash.bcrypt"

    def test_shadow_context_detection(self):
        from hashaxe.identify.classifier import classify

        result = classify(
            "root:$6$rounds=5000$saltsalt$abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:19000:0:99999:7:::"
        )
        assert result.format_id == "hash.sha512crypt"
        assert result.context.get("source") == "shadow_file"
        assert result.context.get("username") == "root"


class TestAttackRecommender:
    def test_recommend_trivial(self):
        from hashaxe.identify.recommender import recommend

        plan = recommend("hash.md5", hashcat_mode=0, difficulty="TRIVIAL")
        assert len(plan.phases) >= 3
        assert plan.phases[0].success_probability == "high"
        assert plan.gpu_recommended is False

    def test_recommend_slow(self):
        from hashaxe.identify.recommender import recommend

        plan = recommend("hash.bcrypt", hashcat_mode=3200, difficulty="SLOW")
        assert len(plan.phases) >= 1
        assert plan.gpu_recommended is True
        assert any("GPU" in n for n in plan.notes)

    def test_recommend_medium(self):
        from hashaxe.identify.recommender import recommend

        plan = recommend("hash.sha512crypt", hashcat_mode=1800, difficulty="MEDIUM")
        assert plan.gpu_recommended is True

    def test_recommend_from_classification(self):
        from hashaxe.identify.classifier import classify
        from hashaxe.identify.recommender import recommend_from_classification

        c = classify("$2b$12$VuqZfLz.GOuU7qDxKXxKNuJPjFdHTmoWnPiJfbNSPYUVqC3BoOiYe")
        plan = recommend_from_classification(c)
        assert plan.hash_type == "hash.bcrypt"
        assert plan.hashcat_mode == 3200


class TestMITREMapper:
    def test_kerberoast_mapping(self):
        from hashaxe.identify.mitre import get_mitre_mappings

        mappings = get_mitre_mappings("network.krb5tgs_rc4")
        assert len(mappings) >= 1
        assert mappings[0].technique_id == "T1558.003"
        assert "Kerberoast" in mappings[0].technique_name

    def test_asrep_mapping(self):
        from hashaxe.identify.mitre import get_mitre_mappings

        mappings = get_mitre_mappings("network.krb5asrep_rc4")
        assert mappings[0].technique_id == "T1558.004"

    def test_dcc2_mapping(self):
        from hashaxe.identify.mitre import get_mitre_mappings

        mappings = get_mitre_mappings("network.dcc2")
        assert "T1003.005" in mappings[0].technique_id

    def test_dpapi_mapping(self):
        from hashaxe.identify.mitre import get_mitre_mappings

        mappings = get_mitre_mappings("disk.dpapi")
        assert "T1555" in mappings[0].technique_id

    def test_cisco_mapping(self):
        from hashaxe.identify.mitre import get_mitre_mappings

        mappings = get_mitre_mappings("network.cisco_type8")
        assert len(mappings) >= 1
        assert "T1552" in mappings[0].technique_id

    def test_ansible_mapping(self):
        from hashaxe.identify.mitre import get_mitre_mappings

        mappings = get_mitre_mappings("token.ansible_vault")
        assert len(mappings) >= 1

    def test_unknown_format(self):
        from hashaxe.identify.mitre import get_mitre_mappings

        mappings = get_mitre_mappings("does.not.exist")
        assert len(mappings) == 0

    def test_get_all_mapped(self):
        from hashaxe.identify.mitre import get_all_mapped_formats

        formats = get_all_mapped_formats()
        assert len(formats) >= 15

    def test_report_generation(self):
        from hashaxe.identify.mitre import generate_mitre_report

        report = generate_mitre_report(["network.krb5tgs_rc4", "network.dcc2"])
        assert "T1558.003" in report
        assert "T1003.005" in report
        assert "MITRE" in report


class TestEndToEndPipeline:
    """Test the full identify → classify → recommend → MITRE pipeline."""

    def test_full_pipeline_kerberoast(self):
        from hashaxe.identify.classifier import classify
        from hashaxe.identify.mitre import get_mitre_mappings
        from hashaxe.identify.recommender import recommend_from_classification

        h = "$krb5tgs$23$*user$REALM$test/spn*$aaaa1111bbbb2222cccc3333dddd4444$eeeeffff00001111"

        # Classify
        c = classify(h)
        assert c.format_id == "network.krb5tgs_rc4"
        assert c.hashcat_mode == 13100

        # Recommend
        plan = recommend_from_classification(c)
        assert len(plan.phases) >= 1

        # MITRE
        mappings = get_mitre_mappings(c.format_id)
        assert mappings[0].technique_id == "T1558.003"

    def test_full_pipeline_dcc2(self):
        from hashaxe.identify.classifier import classify
        from hashaxe.identify.mitre import get_mitre_mappings
        from hashaxe.identify.recommender import recommend_from_classification

        h = "$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f"

        c = classify(h)
        assert c.format_id == "network.dcc2"

        plan = recommend_from_classification(c)
        assert plan.gpu_recommended is True

        mappings = get_mitre_mappings(c.format_id)
        assert "T1003" in mappings[0].technique_id
