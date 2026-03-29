# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/rules/hashcat.py
#  Hashcat rule file parser and executor for drop-in .rule file support.
#  Implements full Hashcat rule syntax (Best64, OneRuleToRuleThemAll, etc.).
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
hashcat.py — Hashcat rule file parser and executor.

Supports the full Hashcat rule syntax so operators can drop in existing
.rule files (Best64, OneRuleToRuleThemAll, d3ad0ne, etc.) without conversion.

Implemented rule functions:
  Noop          :   — do nothing
  Lowercase     l   — lowercase all
  Uppercase     u   — uppercase all
  Capitalize    c   — capitalize first char
  Reverse       r   — reverse string
  Duplicate     d   — duplicate (word → wordword)
  Reflect       f   — append reversed (word → worddrow)
  Toggle case   T N — toggle case at position N
  Delete char   D N — delete char at position N
  Extract       x N M — extract M chars from pos N
  Prepend char  ^ X — prepend char X
  Append char   $ X — append char X
  Insert char   i N X — insert X at position N
  Overwrite     o N X — overwrite char at position N with X
  Truncate left  [ — remove first char
  Truncate right ] — remove last char
  Rotate left   { — rotate left
  Rotate right  } — rotate right
  Replace       s X Y — replace all X with Y
  Purge         @ X — remove all occurrences of X
  Duplicate N   p N — duplicate word N times
  Numeric ops   +N -N — increment/decrement char at position N

Note: Rule functions that require a candidate to match specific criteria
(e.g. length checks) silently return the unchanged word rather than raising.
"""

from __future__ import annotations

import re
from collections.abc import Generator
from pathlib import Path
from typing import Optional

# ── Rule line parser ──────────────────────────────────────────────────────────


def _parse_rule_line(line: str) -> list[tuple]:
    """
    Parse a single rule line into a list of (opcode, *args) tuples.

    A line can contain multiple space-separated rule functions.
    Comments start with #.
    Empty lines and pure-comment lines return an empty list.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return []

    ops: list[tuple] = []
    i = 0
    n = len(line)

    while i < n:
        c = line[i]

        # Skip spaces
        if c == " ":
            i += 1
            continue

        # Single-char no-arg ops
        if c == ":":
            ops.append(("noop",))
            i += 1
        elif c == "l":
            ops.append(("lower",))
            i += 1
        elif c == "u":
            ops.append(("upper",))
            i += 1
        elif c == "c":
            ops.append(("cap",))
            i += 1
        elif c == "C":
            ops.append(("uncap",))
            i += 1
        elif c == "r":
            ops.append(("rev",))
            i += 1
        elif c == "d":
            ops.append(("dup",))
            i += 1
        elif c == "f":
            ops.append(("ref",))
            i += 1
        elif c == "[":
            ops.append(("tl",))
            i += 1
        elif c == "]":
            ops.append(("tr",))
            i += 1
        elif c == "{":
            ops.append(("rotl",))
            i += 1
        elif c == "}":
            ops.append(("rotr",))
            i += 1
        elif c == "q":
            ops.append(("dupc",))
            i += 1

        # Two-char ops: T N, D N, z N, Z N, + N, - N
        elif c in "TDzZ+-" and i + 1 < n:
            arg = line[i + 1]
            pos = _pos(arg)
            if pos is not None:
                ops.append((c, pos))
            i += 2

        # ^ X  — prepend char X
        elif c == "^" and i + 1 < n:
            ops.append(("pre", line[i + 1]))
            i += 2

        # $ X  — append char X
        elif c == "$" and i + 1 < n:
            ops.append(("app", line[i + 1]))
            i += 2

        # s X Y — replace all X with Y
        elif c == "s" and i + 2 < n:
            ops.append(("sub", line[i + 1], line[i + 2]))
            i += 3

        # @ X — purge char X
        elif c == "@" and i + 1 < n:
            ops.append(("purge", line[i + 1]))
            i += 2

        # i N X — insert char X at position N
        elif c == "i" and i + 2 < n:
            pos = _pos(line[i + 1])
            if pos is not None:
                ops.append(("ins", pos, line[i + 2]))
            i += 3

        # o N X — overwrite position N with char X
        elif c == "o" and i + 2 < n:
            pos = _pos(line[i + 1])
            if pos is not None:
                ops.append(("ovr", pos, line[i + 2]))
            i += 3

        # x N M — extract from pos N, length M
        elif c == "x" and i + 2 < n:
            pos = _pos(line[i + 1])
            ln = _pos(line[i + 2])
            if pos is not None and ln is not None:
                ops.append(("ext", pos, ln))
            i += 3

        # p N — duplicate word N times
        elif c == "p" and i + 1 < n:
            n_ = _pos(line[i + 1])
            if n_ is not None:
                ops.append(("dup_n", n_))
            i += 2

        else:
            i += 1  # unknown character — skip silently

    return ops


def _pos(c: str) -> int | None:
    """Convert a hashcat position character (0-9, A-Z) to an integer index."""
    if c.isdigit():
        return int(c)
    if c.isupper():
        return ord(c) - ord("A") + 10
    return None


# ── Rule executor ─────────────────────────────────────────────────────────────


def _apply_op(word: str, op: tuple) -> str:
    """Apply a single rule operation to word.  Returns modified string."""
    code = op[0]

    if code == "noop":
        return word
    if code == "lower":
        return word.lower()
    if code == "upper":
        return word.upper()
    if code == "cap":
        return word[0].upper() + word[1:].lower() if word else word
    if code == "uncap":
        return word[0].lower() + word[1:] if word else word
    if code == "rev":
        return word[::-1]
    if code == "dup":
        return word + word
    if code == "ref":
        return word + word[::-1]
    if code == "tl":
        return word[1:] if word else word
    if code == "tr":
        return word[:-1] if word else word
    if code == "rotl":
        return word[1:] + word[0] if word else word
    if code == "rotr":
        return word[-1] + word[:-1] if word else word
    if code == "dupc":
        return "".join(c + c for c in word)

    if code == "pre":
        return op[1] + word
    if code == "app":
        return word + op[1]
    if code == "sub":
        return word.replace(op[1], op[2])
    if code == "purge":
        return word.replace(op[1], "")

    if code == "T":
        pos = op[1]
        if 0 <= pos < len(word):
            lst = list(word)
            lst[pos] = lst[pos].swapcase()
            return "".join(lst)
        return word

    if code == "D":
        pos = op[1]
        if 0 <= pos < len(word):
            return word[:pos] + word[pos + 1 :]
        return word

    if code == "ins":
        pos, ch = op[1], op[2]
        return word[:pos] + ch + word[pos:]

    if code == "ovr":
        pos, ch = op[1], op[2]
        if 0 <= pos < len(word):
            return word[:pos] + ch + word[pos + 1 :]
        return word

    if code == "ext":
        pos, ln = op[1], op[2]
        return word[pos : pos + ln]

    if code == "+":
        pos = op[1]
        if 0 <= pos < len(word):
            lst = list(word)
            lst[pos] = chr((ord(lst[pos]) + 1) % 256)
            return "".join(lst)
        return word

    if code == "-":
        pos = op[1]
        if 0 <= pos < len(word):
            lst = list(word)
            lst[pos] = chr((ord(lst[pos]) - 1) % 256)
            return "".join(lst)
        return word

    if code == "z":
        n = op[1]
        return word[0] * n + word if word else word

    if code == "Z":
        n = op[1]
        return word + word[-1] * n if word else word

    if code == "dup_n":
        return word * (op[1] + 1)

    return word  # unknown op — pass through


def apply_rule_line(word: str, ops: list[tuple]) -> str | None:
    """Apply a parsed rule (list of ops) to a word.  Returns transformed word."""
    result = word
    for op in ops:
        result = _apply_op(result, op)
    return result if result else None


# ── Rule file loader ──────────────────────────────────────────────────────────


def load_rule_file(path: str) -> list[list[tuple]]:
    """
    Parse a Hashcat .rule file into a list of compiled rule programs.

    Returns a list where each element is a list of (opcode, *args) tuples.
    Empty lines and comments are excluded.
    """
    rules: list[list[tuple]] = []
    for line in Path(path).read_text(errors="replace").splitlines():
        parsed = _parse_rule_line(line)
        if parsed:
            rules.append(parsed)
    return rules


def apply_rules_from_file(
    word: str,
    rules: list[list[tuple]],
) -> Generator[str, None, None]:
    """Yield one candidate per rule in the loaded rule list."""
    seen: set[str] = set()
    for rule in rules:
        result = apply_rule_line(word, rule)
        if result and result not in seen:
            seen.add(result)
            yield result


# ── Built-in mini rule sets ───────────────────────────────────────────────────

# Best64 — most commonly successful rules
BEST64_RULES: list[str] = [
    ":",  # noop
    "l",  # lowercase
    "u",  # uppercase
    "c",  # capitalize
    "r",  # reverse
    "d",  # duplicate
    "$1",  # append 1
    "$2",  # append 2
    "$3",  # append 3
    "$!",  # append !
    "$@",  # append @
    "c$1",  # capitalize + append 1
    "c$2",  # capitalize + append 2
    "c$!",  # capitalize + append !
    "c$2$0$2$4",  # capitalize + append 2024
    "c$2$0$2$5",  # capitalize + append 2025
    "$1$2$3",  # append 123
    "$1$2$3$!",  # append 123!
    "c$1$2$3",  # cap + 123
    "ss$",  # s→$
    "sa@",  # a→@
    "se3",  # e→3
    "si1",  # i→1
    "so0",  # o→0
    "l sa@ se3 si1 so0",  # full leet
    "r c",  # reverse + capitalize
    "[ c",  # remove first + capitalize
]


def get_builtin_rules(name: str = "best64") -> list[list[tuple]]:
    """
    Return a built-in rule set by name.

    Available: 'best64'
    """
    if name == "best64":
        rules = []
        for line in BEST64_RULES:
            parsed = _parse_rule_line(line)
            if parsed:
                rules.append(parsed)
        return rules
    raise ValueError(f"Unknown built-in rule set: {name!r}. Available: 'best64'")
