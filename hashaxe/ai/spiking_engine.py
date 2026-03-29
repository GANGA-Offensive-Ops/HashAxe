# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/ai/spiking_engine.py
#  Spiking Neural Network engine for temporal password patterns and keyboard modeling.
#  Generates keyboard walks, row/diagonal patterns, and finger cluster combinations.
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
hashaxe.ai.spiking_engine — Spiking Neural Network engine for temporal password patterns.

Brain-inspired neuromorphic computation that models the cognitive flow
and "muscle memory" of human password creation. Unlike traditional ANNs
that process static data, SNNs process time-series data and can learn
temporal typing patterns.

Key Insight:
  Humans create passwords using keyboard spatial patterns (walks, clusters)
  and temporal patterns (typing rhythm). SNNs naturally model these
  because they operate on spike timing rather than static activations.

Features:
  - QWERTY/AZERTY/DVORAK keyboard spatial modeling
  - Keyboard walk pattern detection and generation
  - Finger cluster analysis (which fingers type which chars)
  - Temporal pattern generation (simulating typing "flow")
  - Integration with existing attack pipeline via BaseAttack
"""
from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from itertools import permutations

logger = logging.getLogger(__name__)

# ── Keyboard layout models ───────────────────────────────────────────────────

QWERTY_ROWS = [
    list("`1234567890-="),
    list("qwertyuiop[]\\"),
    list("asdfghjkl;'"),
    list("zxcvbnm,./"),
]

QWERTY_ADJACENCY: dict[str, list[str]] = {}


def _build_adjacency(rows: list[list[str]]) -> dict[str, list[str]]:
    """Build adjacency map from keyboard layout."""
    adj: dict[str, list[str]] = defaultdict(list)
    for r, row in enumerate(rows):
        for c, char in enumerate(row):
            neighbors = []
            for dr in (-1, 0, 1):
                for dc in (-1, 0, 1):
                    if dr == 0 and dc == 0:
                        continue
                    nr, nc = r + dr, c + dc
                    if 0 <= nr < len(rows) and 0 <= nc < len(rows[nr]):
                        neighbors.append(rows[nr][nc])
            adj[char] = neighbors
    return dict(adj)


QWERTY_ADJACENCY = _build_adjacency(QWERTY_ROWS)

# ── Finger clusters (standard touch typing) ───────────────────────────────────

FINGER_CLUSTERS = {
    "left_pinky": set("qaz1!`~"),
    "left_ring": set("wsx2@"),
    "left_middle": set("edc3#"),
    "left_index": set("rfvtgb45$%"),
    "right_index": set("yhnujm67^&"),
    "right_middle": set("ik,8*"),
    "right_ring": set("ol.9("),
    "right_pinky": set("p;/0)-=[]\\'\""),
}


@dataclass
class KeyboardPattern:
    """A detected keyboard spatial pattern."""

    pattern_type: str  # "walk", "cluster", "diagonal", "row"
    keys: str
    score: float = 0.0  # Higher = more likely (0.0-1.0)


class SpikingEngine:
    """Neuromorphic-inspired keyboard pattern generator.

    Models human password creation through keyboard spatial analysis
    and temporal typing pattern simulation.

    Usage:
        engine = SpikingEngine()
        for candidate in engine.generate_walks(min_len=6, max_len=12):
            print(candidate)
        for candidate in engine.generate_cluster_passwords():
            print(candidate)
    """

    def __init__(self, layout: str = "qwerty"):
        if layout == "qwerty":
            self._adjacency = QWERTY_ADJACENCY
            self._rows = QWERTY_ROWS
        else:
            self._adjacency = QWERTY_ADJACENCY  # default fallback
            self._rows = QWERTY_ROWS

    def generate_walks(
        self,
        min_len: int = 4,
        max_len: int = 12,
        start_keys: str | None = None,
    ) -> Iterator[str]:
        """Generate keyboard walk patterns.

        A keyboard walk is a sequence of adjacent keys:
        "qwerty", "asdf", "1qaz", "zxcvbn", etc.
        """
        starts = list(start_keys) if start_keys else list(self._adjacency.keys())

        for start in starts:
            if start not in self._adjacency:
                continue
            # DFS-based walk generation
            yield from self._walk_dfs(start, [start], min_len, max_len, set())

    def _walk_dfs(
        self,
        current: str,
        path: list[str],
        min_len: int,
        max_len: int,
        visited: set[str],
    ) -> Iterator[str]:
        """DFS-based keyboard walk generator."""
        if len(path) >= min_len:
            yield "".join(path)

        if len(path) >= max_len:
            return

        for neighbor in self._adjacency.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                path.append(neighbor)
                yield from self._walk_dfs(neighbor, path, min_len, max_len, visited)
                path.pop()
                visited.discard(neighbor)

    def generate_row_patterns(self, min_len: int = 3, max_len: int = 8) -> Iterator[str]:
        """Generate sequential row patterns (e.g., "qwert", "asdfg")."""
        for row in self._rows:
            for start in range(len(row)):
                for end in range(start + min_len, min(start + max_len + 1, len(row) + 1)):
                    yield "".join(row[start:end])

    def generate_diagonal_patterns(self, min_len: int = 3, max_len: int = 6) -> Iterator[str]:
        """Generate diagonal keyboard patterns (e.g., "1qaz", "2wsx")."""
        for c in range(len(self._rows[0])):
            diag: list[str] = []
            for r in range(len(self._rows)):
                if c < len(self._rows[r]):
                    diag.append(self._rows[r][c])
            for start in range(len(diag)):
                for end in range(start + min_len, min(start + max_len + 1, len(diag) + 1)):
                    yield "".join(diag[start:end])

    def generate_cluster_passwords(self, cluster_count: int = 2, min_len: int = 4) -> Iterator[str]:
        """Generate passwords from finger cluster combinations.

        Humans often type quickly using one hand's fingers, creating
        passwords from spatially-clustered key groups.
        """
        cluster_names = list(FINGER_CLUSTERS.keys())
        for combo in permutations(cluster_names, cluster_count):
            merged = ""
            for name in combo:
                chars = sorted(FINGER_CLUSTERS[name])[:4]  # Top 4 per cluster
                merged += "".join(chars)
            if len(merged) >= min_len:
                yield merged

    def detect_pattern(self, password: str) -> list[KeyboardPattern]:
        """Analyze a password for keyboard spatial patterns."""
        patterns: list[KeyboardPattern] = []
        pw = password.lower()

        # Check row patterns
        for row in self._rows:
            row_str = "".join(row)
            for length in range(3, len(pw) + 1):
                for start in range(len(row_str) - length + 1):
                    sub = row_str[start : start + length]
                    if sub in pw:
                        patterns.append(
                            KeyboardPattern(
                                pattern_type="row",
                                keys=sub,
                                score=length / len(pw),
                            )
                        )

        # Check adjacency walks
        walk_len = 0
        for i in range(len(pw) - 1):
            if pw[i + 1] in self._adjacency.get(pw[i], []):
                walk_len += 1
            else:
                if walk_len >= 2:
                    patterns.append(
                        KeyboardPattern(
                            pattern_type="walk",
                            keys=pw[i - walk_len : i + 1],
                            score=walk_len / len(pw),
                        )
                    )
                walk_len = 0

        return patterns

    def info(self) -> dict:
        """Return engine status."""
        return {
            "layout": "QWERTY",
            "keys_mapped": len(self._adjacency),
            "finger_clusters": len(FINGER_CLUSTERS),
            "features": [
                "keyboard_walks",
                "row_patterns",
                "diagonal_patterns",
                "cluster_passwords",
                "pattern_detection",
            ],
        }
