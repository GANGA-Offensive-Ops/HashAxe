# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/display.py
#  Terminal display and progress rendering with ANSI support.
#  Provides banner, progress bar, result box, key info, session list,
#  benchmark tables, GPU status, distributed worker status, and AI analysis
#  display. Designed to degrade gracefully on terminals without ANSI support.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️  WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️  Version 2.0.1 — Production Release 💀  (2026-03-27)
# ==========================================================================================
"""
display.py — Terminal display and progress rendering.

Provides:
  • Coloured banner with gradient simulation
  • Real-time progress bar with speed, ETA, and worker stats
  • Result box (found / not found)
  • Key info table
  • Session list table
  • Benchmark summary table
  • GPU / accelerator status table
  • Distributed worker status panel
  • AI attack analysis display
  • Hash identification result panel
  • Multi-hash hashaxe summary
  • PQC / quantum threat advisory panel

All output is funnelled through a single ``Display`` instance so tests can
suppress it cleanly, and the distributed layer can call it safely from
multiple threads (a ``threading.Lock`` guards the progress line).

Requires: Python ≥ 3.12  (uses PEP 604 union syntax, PEP 695 not required)
No mandatory third-party dependencies — optional ``rich`` detected at import
time and used only for the live dashboard (``Display.dashboard``).
"""

from __future__ import annotations

import os
import re
import sys
import time
import threading
import shutil
from datetime import datetime, timezone
from typing import Any

# ── Optional rich import (non-fatal) ─────────────────────────────────────────
try:
    from rich.console import Console as _RichConsole
    from rich.panel import Panel as _Panel
    from rich.table import Table as _Table
    from rich.text import Text as _Text
    from rich import box as _box
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# ANSI detection
# ─────────────────────────────────────────────────────────────────────────────

def _ansi_supported() -> bool:
    """True if the terminal supports ANSI escape sequences."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7
            )
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_USE_ANSI = _ansi_supported()

# ── Colour constants ──────────────────────────────────────────────────────────
# Standard colours
RED           = "\033[31m" if _USE_ANSI else ""
BRIGHT_RED    = "\033[91m" if _USE_ANSI else ""
GREEN         = "\033[32m" if _USE_ANSI else ""
BRIGHT_GREEN  = "\033[92m" if _USE_ANSI else ""
YELLOW        = "\033[33m" if _USE_ANSI else ""
BRIGHT_YELLOW = "\033[93m" if _USE_ANSI else ""
BLUE          = "\033[34m" if _USE_ANSI else ""
BRIGHT_BLUE   = "\033[94m" if _USE_ANSI else ""
PURPLE        = "\033[35m" if _USE_ANSI else ""
BRIGHT_PURPLE = "\033[95m" if _USE_ANSI else ""
CYAN          = "\033[36m" if _USE_ANSI else ""
BRIGHT_CYAN   = "\033[96m" if _USE_ANSI else ""
WHITE         = "\033[97m" if _USE_ANSI else ""
BRIGHT_WHITE  = "\033[97m" if _USE_ANSI else ""    # alias — 97 is already bright
GREY          = "\033[90m" if _USE_ANSI else ""
PINK          = "\033[35m" if _USE_ANSI else ""

# Formatting
BOLD          = "\033[1m"  if _USE_ANSI else ""
DIM           = "\033[2m"  if _USE_ANSI else ""
ITALIC        = "\033[3m"  if _USE_ANSI else ""
UNDERLINE     = "\033[4m"  if _USE_ANSI else ""
BLINK         = "\033[5m"  if _USE_ANSI else ""
REVERSE       = "\033[7m"  if _USE_ANSI else ""
RESET         = "\033[0m"  if _USE_ANSI else ""

# ── Semantic colour aliases (use these in new code) ───────────────────────────
C_SUCCESS  = BRIGHT_GREEN
C_FAIL     = BRIGHT_RED
C_WARN     = BRIGHT_YELLOW
C_INFO     = BRIGHT_CYAN
C_DIM      = GREY
C_VALUE    = WHITE
C_KEY      = CYAN
C_HASH     = YELLOW
C_SPEED    = GREEN
C_CRITICAL = f"{BOLD}{BRIGHT_RED}"

# ── Speed-tier colours for progress (changes with current rate) ───────────────
def _speed_colour(speed: float, baseline: float = 1.0) -> str:
    """Return an ANSI colour code reflecting speed relative to baseline."""
    if not _USE_ANSI:
        return ""
    ratio = speed / baseline if baseline > 0 else 0
    if ratio >= 2.0:
        return BRIGHT_GREEN
    if ratio >= 1.0:
        return GREEN
    if ratio >= 0.5:
        return YELLOW
    return BRIGHT_RED


# ─────────────────────────────────────────────────────────────────────────────
# Banner  (hardcoded — never call pyfiglet at runtime for zero-latency start)
# ─────────────────────────────────────────────────────────────────────────────
BANNER = f"""
{BOLD}{PURPLE}
     ██╗  ██╗ █████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
     ██║  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗╚██╗██╔╝██╔════╝
     ███████║███████║███████╗███████║███████║ ╚███╔╝ █████╗  
     ██╔══██║██╔══██║╚════██║██╔══██║██╔══██║ ██╔██╗ ██╔══╝  
     ██║  ██║██║  ██║███████║██║  ██║██║  ██║██╔╝ ██╗███████╗
     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
{RESET}{CYAN} ────────────────────────────────────────────────────────────────{RESET}
{BOLD}{PINK}              HashAxe V1 {RESET}{BOLD}{BRIGHT_WHITE} Multi-Format Hash Cracker{RESET}
{BOLD}{BRIGHT_YELLOW}  43 Formats · SSH/PPK/Archives/Docs/DB/Network/Kerberos/DPAPI/+{RESET}
{BOLD}{BRIGHT_CYAN}       GPU-Accelerated · Distributed · AI-Powered · Auto-Pwn{RESET}
{BOLD}{BRIGHT_RED}           GANGA Offensive Ops  ·  Authorized Use Only{RESET}
{CYAN} ────────────────────────────────────────────────────────────────{RESET}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers  (module-level, no class dependency)
# ─────────────────────────────────────────────────────────────────────────────

# Compiled once — strips every ANSI CSI escape sequence from a string so that
# len() returns the true visible column width rather than the byte count.
_ANSI_ESC_RE: re.Pattern[str] = re.compile(r"\033\[[0-9;]*m")


def _visible_len(s: str) -> int:
    """Return the visible column width of *s*, stripping all ANSI escape codes."""
    return len(_ANSI_ESC_RE.sub("", s))


def _fmt_time(seconds: float) -> str:
    """Human-readable duration string from a float of seconds."""
    if seconds < 0:
        return "n/a"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3_600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86_400:
        return f"{seconds / 3_600:.1f}h"
    if seconds < 2_592_000:
        return f"{seconds / 86_400:.1f}d"
    return f"{seconds / 2_592_000:.1f}mo"


def _fmt_speed(hps: float) -> str:
    """Format a hash-per-second value with SI prefix."""
    if hps >= 1e12:
        return f"{hps / 1e12:.2f} TH/s"
    if hps >= 1e9:
        return f"{hps / 1e9:.2f} GH/s"
    if hps >= 1e6:
        return f"{hps / 1e6:.2f} MH/s"
    if hps >= 1e3:
        return f"{hps / 1e3:.1f} KH/s"
    return f"{hps:.1f} H/s"


def _term_width(fallback: int = 80) -> int:
    return shutil.get_terminal_size((fallback, 24)).columns


def _rule(char: str = "─", width: int | None = None) -> str:
    w = width or _term_width()
    return char * w


def _ts() -> str:
    """ISO-8601 timestamp in UTC, for log-mode output."""
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


# ─────────────────────────────────────────────────────────────────────────────
# Display class
# ─────────────────────────────────────────────────────────────────────────────

class Display:
    """
    All terminal output funnelled through one instance.

    Thread-safe progress bar output via ``_lock``.
    Existing callers are source-compatible with v1.0.0 — all original
    method signatures are preserved exactly.

    New in v2.0.0
    ─────────────
    • ``debug()``           — verbose-only diagnostic messages
    • ``section()``         — bold section header rule
    • ``status()``          — ephemeral one-line status (overwritten)
    • ``gpu_status()``      — GPU / OpenCL / CUDA accelerator table
    • ``worker_status()``   — distributed worker health panel
    • ``hashaxe_summary()``   — multi-hash batch result table
    • ``hash_id_result()``  — identified hash type panel
    • ``ai_analysis()``     — AI attack mode analysis display
    • ``pqc_advisory()``    — PQC / quantum threat advisory
    • ``rule()``            — horizontal rule (thin wrapper)
    • ``fmt_speed()``       — static speed formatter (public proxy)
    • ``fmt_time()``        — static time formatter (public proxy)
    """

    __slots__ = (
        "verbose",
        "quiet",
        "_last_bar_len",
        "_lock",
        "_bar_baseline",
        "_start_time",
    )

    def __init__(self, verbose: bool = False, quiet: bool = False) -> None:
        self.verbose                     = verbose
        self.quiet                       = quiet
        self._last_bar_len: int          = 0
        self._lock                       = threading.Lock()
        self._bar_baseline: float | None = None   # None until first non-zero speed
        self._start_time: float          = time.monotonic()

    # ── Static / class utilities ──────────────────────────────────────────────

    @staticmethod
    def fmt_speed(hps: float) -> str:
        return _fmt_speed(hps)

    @staticmethod
    def fmt_time(seconds: float) -> str:
        return _fmt_time(seconds)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _rounds_note(self, rounds: int) -> str:
        if rounds >= 64:  return "very slow  (~1 pw/s/core) — will take a while"
        if rounds >= 32:  return "slow       (~2–4 pw/s/core)"
        if rounds >= 16:  return "standard   (~5–10 pw/s/core)"
        return                   "fast       (>10 pw/s/core)"

    def _print(self, *args: Any, **kwargs: Any) -> None:
        """Write to stdout, no-op when quiet."""
        if not self.quiet:
            print(*args, **kwargs)

    def _eprint(self, *args: Any, **kwargs: Any) -> None:
        """Write to stderr regardless of quiet flag."""
        print(*args, file=sys.stderr, **kwargs)

    # ── Banners / headers ─────────────────────────────────────────────────────

    def banner(self) -> None:
        """Print the ASCII art banner. No-op when quiet."""
        if not self.quiet:
            print(BANNER)

    def section(self, title: str, char: str = "═") -> None:
        """
        Print a prominent section header.

        Example output:
            ══════════════════ GPU Acceleration ══════════════════
        """
        if self.quiet:
            return
        w = _term_width()
        pad = max(0, (w - len(title) - 4) // 2)
        left  = char * pad
        right = char * (w - pad - len(title) - 2)
        self._print(f"\n{BOLD}{PURPLE}{left} {title} {right}{RESET}")

    def rule(self, char: str = "─", width: int | None = None) -> None:
        """Print a plain horizontal rule."""
        if not self.quiet:
            self._print(f"{GREY}{_rule(char, width)}{RESET}")

    def target_info(self, target: Any, handler: Any) -> None:
        """Print format-specific metadata table."""
        if self.quiet:
            return

        preview = getattr(target, "source_path", None) or "raw input"
        self._print(f"{BOLD}[*]{RESET} Target    : {C_KEY}{preview}{RESET}")

        info = handler.display_info(target)
        for k, v in info.items():
            if k == "Rounds":
                cost_note = f"{C_DIM}  ← {self._rounds_note(int(v))}{RESET}"
                self._print(f"    {k:<10}: {C_HASH}{v}{RESET}{cost_note}")
            else:
                self._print(f"    {k:<10}: {C_HASH}{v}{RESET}")

        if not getattr(target, "is_encrypted", True):
            self._print(f"\n{C_SUCCESS}[+] Target is NOT encrypted — no passphrase needed.{RESET}")

    def attack_header(
        self,
        wordlist:          str,
        workers:           int,
        use_rules:         bool,
        total_candidates:  int,
        mode:              str          = "wordlist",
        mask:              str | None   = None,
        resuming:          bool         = False,
        *,
        rule_file:         str | None   = None,
        hybrid_mask:       str | None   = None,
        charset:           str | None   = None,
        ai_enabled:        bool         = False,
        gpu_workers:       int          = 0,
    ) -> None:
        """
        Print attack startup information.

        v2 additions (keyword-only, all optional):
          rule_file   — show active rule file name
          hybrid_mask — show hybrid mask alongside wordlist
          charset     — show custom charset
          ai_enabled  — show AI augmentation notice
          gpu_workers — show GPU worker count
        """
        if self.quiet:
            return

        prefix = (
            f"{C_SUCCESS}[~]{RESET} Resuming"
            if resuming
            else f"{BOLD}[*]{RESET} Starting"
        )
        self._print(f"\n{prefix} {C_HASH}{mode}{RESET} attack...")
        self._print(f"{BOLD}[*]{RESET} Wordlist  : {C_KEY}{wordlist}{RESET}")

        if mask:
            self._print(f"{BOLD}[*]{RESET} Mask      : {C_KEY}{mask}{RESET}")
        if hybrid_mask:
            self._print(f"{BOLD}[*]{RESET} Hyb. mask : {C_KEY}{hybrid_mask}{RESET}")
        if charset:
            self._print(f"{BOLD}[*]{RESET} Charset   : {C_KEY}{charset}{RESET}")
        if rule_file:
            self._print(f"{BOLD}[*]{RESET} Rule file : {C_KEY}{rule_file}{RESET}")
        if ai_enabled:
            self._print(f"{BOLD}[*]{RESET} AI        : {BRIGHT_PURPLE}ENABLED — OSINT-tuned mutations{RESET}")

        cpu_tag = f"{C_SUCCESS}{workers}{RESET} CPU"
        gpu_tag = (
            f"  +  {BRIGHT_YELLOW}{gpu_workers}{RESET} GPU"
            if gpu_workers > 0
            else ""
        )
        self._print(f"{BOLD}[*]{RESET} Workers   : {cpu_tag} processes{gpu_tag}")
        self._print(f"{BOLD}[*]{RESET} Rules     : {C_SUCCESS}{'ON' if use_rules else 'OFF'}{RESET}")
        self._print(f"{BOLD}[*]{RESET} Candidates: {C_VALUE}{total_candidates:,}{RESET}")
        self._print()

    # ── Progress bar ──────────────────────────────────────────────────────────

    def progress(
        self,
        tried:   int,
        total:   int,
        speed:   float,
        workers: int,
        width:   int = 38,
    ) -> None:
        """
        Print an in-place progress bar.

        Thread-safe — multiple distributed workers can call this concurrently.
        The speed colour ramp compares against the first non-zero speed seen
        in the session.
        """
        if self.quiet:
            return
        if self.verbose:
            self._verbose_progress(tried, total, speed, workers)
            return

        # Sanitise inputs — clamp to valid ranges so downstream maths never
        # produces negative fills, bogus percentages, or over-wide bars.
        tried = max(0, tried)
        total = max(0, total)
        speed = max(0.0, speed)

        pct = min(1.0, tried / total) if total > 0 else 0.0

        # ETA — show "--:--:--" when total is unknown (total == 0) rather than
        # the misleading "00:00:00" that the original code produced.
        if speed > 0 and total > 0:
            remaining = max(0.0, (total - tried) / speed)
            eta = (
                f"{int(remaining) // 3600:02d}:"
                f"{(int(remaining) % 3600) // 60:02d}:"
                f"{int(remaining) % 60:02d}"
            )
        else:
            eta = "--:--:--"

        total_s = f"{total:,}" if total > 0 else "?"
        pct_s   = f"{pct * 100:.1f}%" if total > 0 else "?"
        spd_s   = _fmt_speed(speed)

        # Compute bar width from the visible (ANSI-stripped) length of a
        # placeholder line so that escape-code bytes are never counted as
        # terminal columns.  This fixes the bar-sizing drift that occurred
        # when _USE_ANSI was True and the old code used len() on the raw line.
        _sample = (
            f"[{'█' * 5}] "
            f"{tried:>12,}/{total_s} "
            f"({pct_s}) "
            f"{spd_s} "
            f"ETA {eta}  "
        )
        term_cols = _term_width()
        reserved  = _visible_len(_sample)
        bar_width = max(5, min(term_cols - reserved, width))

        filled = int(bar_width * pct)
        bar    = "█" * filled + "░" * (bar_width - filled)

        # Initialise baseline inside the lock so that concurrent workers
        # cannot both pass the None-check and write simultaneously.
        # Using None as sentinel avoids the original collision where a real
        # speed of exactly 1.0 H/s was indistinguishable from the init value.
        with self._lock:
            if speed > 0 and self._bar_baseline is None:
                self._bar_baseline = speed
            baseline = self._bar_baseline if self._bar_baseline is not None else (speed if speed > 0 else 1.0)

        sc = _speed_colour(speed, baseline)

        line = (
            f"\r{CYAN}[{bar}]{RESET} "
            f"{C_VALUE}{tried:>12,}/{total_s}{RESET} "
            f"{YELLOW}({pct_s}){RESET} "
            f"{sc}{spd_s}{RESET} "
            f"{GREY}ETA {eta}{RESET}  "
        )

        # Store and use the *visible* column width, not the raw byte length.
        # On ANSI terminals len(line) is significantly inflated by escape
        # sequences, making the non-ANSI padding calculation wrong.
        visible = _visible_len(line)

        with self._lock:
            if _USE_ANSI:
                print(f"\r\033[K{line.lstrip(chr(13))}", end="", flush=True)
            else:
                pad = max(0, self._last_bar_len - visible)
                print(f"{line}{' ' * pad}", end="", flush=True)
            self._last_bar_len = visible

    def _verbose_progress(
        self,
        tried:   int,
        total:   int,
        speed:   float,
        workers: int,
    ) -> None:
        # Wall-clock elapsed via monotonic timer — not tried/speed which gives
        # an estimated processing time rather than actual time since session start.
        elapsed = time.monotonic() - self._start_time
        pct     = min(100.0, (tried / total * 100)) if total > 0 else 0.0
        self._print(
            f"{GREY}[~]{RESET} [{_ts()}] "
            f"Tried {C_VALUE}{tried:,}{RESET}  "
            f"Speed {C_SPEED}{_fmt_speed(speed)}{RESET}  "
            f"Progress {YELLOW}{pct:.1f}%{RESET}  "
            f"Workers {workers}  "
            f"Elapsed {_fmt_time(elapsed)}",
            flush=True,
        )

    def clear_progress(self) -> None:
        """Erase the progress bar line (or separate the last verbose line)."""
        with self._lock:
            if self.quiet:
                self._last_bar_len = 0
                return
            if self.verbose:
                # In verbose mode each update is a new line, so we only need
                # a plain newline to ensure the result box starts cleanly on
                # its own line rather than running onto the last log entry.
                print(flush=True)
            else:
                print(
                    "\r" + " " * (self._last_bar_len + 5) + "\r",
                    end="",
                    flush=True,
                )
            self._last_bar_len = 0

    # ── Status (ephemeral one-liner, overwritten on next call) ────────────────

    def status(self, msg: str) -> None:
        """Print an ephemeral status line that is overwritten on next call."""
        if self.quiet:
            return
        with self._lock:
            line    = f"\r{GREY}[~]{RESET} {msg}"
            visible = _visible_len(line)
            pad     = max(0, self._last_bar_len - visible)
            print(f"{line}{' ' * pad}", end="", flush=True)
            self._last_bar_len = visible

    # ── Result display ────────────────────────────────────────────────────────

    def found(
        self,
        passphrase: str,
        key_path:   str,
        tried:      int,
        elapsed:    float,
        speed:      float,
        *,
        hash_type:  str | None = None,
        worker_id:  int | None = None,
    ) -> None:
        """
        Print the success box.

        v2 keyword-only additions:
          hash_type  — detected/confirmed hash algorithm
          worker_id  — which distributed worker found it
        """
        self.clear_progress()
        w = 64
        self._print(f"\n{C_SUCCESS}{'═' * w}{RESET}")
        self._print(f"  {C_SUCCESS}{BOLD}✔  PASSPHRASE FOUND!{RESET}")
        self._print(f"{C_SUCCESS}{'═' * w}{RESET}")
        self._print(f"  Key file   : {C_KEY}{key_path}{RESET}")
        self._print(f"  Passphrase : {C_SUCCESS}{BOLD}{passphrase!r}{RESET}")
        if hash_type:
            self._print(f"  Hash type  : {C_HASH}{hash_type}{RESET}")
        self._print(f"  Tried      : {C_VALUE}{tried:,}{RESET} candidates")
        self._print(f"  Time       : {C_VALUE}{_fmt_time(elapsed)}{RESET}")
        self._print(f"  Speed      : {C_VALUE}{_fmt_speed(speed)}{RESET}")
        if worker_id is not None:
            self._print(f"  Worker     : {C_DIM}#{worker_id}{RESET}")
        self._print(f"{C_SUCCESS}{'═' * w}{RESET}\n")

    def not_found(self, tried: int, elapsed: float) -> None:
        """Print the failure box with actionable suggestions."""
        self.clear_progress()
        self._print(f"\n{C_FAIL}[✘] Passphrase NOT found in wordlist.{RESET}")
        self._print(
            f"    Tried    : {tried:,} candidates in {_fmt_time(elapsed)}"
        )
        self._print(f"\n{C_WARN}[?] Suggestions:{RESET}")
        suggestions = [
            "Add --rules for ~60× more mutations per word",
            "Add --mask '?d?d?d?d' to append digit patterns",
            "Use a larger wordlist: kaonashi, weakpass_3, hashes.org",
            "Try --rule-file best64.rule or OneRuleToRuleThemAll.rule",
            "Combine: cat rockyou.txt custom.txt > combined.txt",
            "Enable --ai for OSINT-guided target-specific mutations",
            "Enable --gpu to engage CUDA/OpenCL acceleration",
        ]
        for s in suggestions:
            self._print(f"    • {s}")

    def ssh_verify(self, ok: bool) -> None:
        if ok:
            self._print(
                f"{C_SUCCESS}[+] SSH connection VERIFIED — key + passphrase confirmed.{RESET}"
            )
        else:
            self._print(
                f"{C_WARN}[-] SSH verify failed (key may still be correct){RESET}"
            )

    # ── Benchmark display ─────────────────────────────────────────────────────

    def benchmark_result(
        self,
        key_path:       str,
        rounds:         int,
        speed_per_core: float,
        workers:        int,
        *,
        gpu_speed:      float = 0.0,
        algorithm:      str   = "",
    ) -> None:
        """
        Print benchmark results table.

        v2 keyword-only additions:
          gpu_speed  — combined GPU H/s (0 if no GPU)
          algorithm  — algorithm identifier string
        """
        total_speed     = speed_per_core * workers + gpu_speed
        rockyou_14m     = 14_000_000
        w               = 60

        self._print(f"\n{BOLD}{'─' * w}{RESET}")
        self._print(f"  {BOLD}Benchmark Results{RESET}")
        self._print(f"{'─' * w}")
        self._print(f"  Key            : {key_path}")
        if algorithm:
            self._print(f"  Algorithm      : {C_HASH}{algorithm}{RESET}")
        self._print(f"  KDF rounds     : {rounds}")
        self._print(f"  Speed/core     : {C_HASH}{_fmt_speed(speed_per_core)}{RESET}")
        self._print(f"  CPU Workers    : {workers}")
        if gpu_speed > 0:
            self._print(f"  GPU Speed      : {BRIGHT_YELLOW}{_fmt_speed(gpu_speed)}{RESET}")
        self._print(f"  Total speed    : {C_SUCCESS}{_fmt_speed(total_speed)}{RESET}")
        self._print(f"{'─' * w}")
        self._print(f"  Time estimates ({workers} CPU workers{' + GPU' if gpu_speed else ''}):")
        estimates = [
            ("top 1k   words",  1_000),
            ("top 10k  words",  10_000),
            ("rockyou 14M   ",  rockyou_14m),
            ("+ best64 rule ",  rockyou_14m * 64),
            ("+ top1M rules ",  rockyou_14m * 1_000_000),
        ]
        for label, count in estimates:
            t = _fmt_time(count / total_speed) if total_speed > 0 else "n/a"
            self._print(f"    {label}: {t}")
        self._print(f"{'─' * w}\n")

    # ── Session list ──────────────────────────────────────────────────────────

    def session_list(self, sessions: list[dict[str, Any]]) -> None:
        """Print saved sessions table."""
        if not sessions:
            self._print(f"{C_WARN}No saved sessions found.{RESET}")
            return
        w = 76
        self._print(f"\n{'─' * w}")
        self._print(
            f"  {'NAME':<16}  {'KEY':<22}  {'TRIED':>10}  "
            f"{'ELAPSED':>8}  {'FORMAT':<12}  MODE"
        )
        self._print(f"{'─' * w}")
        for s in sessions:
            elapsed   = _fmt_time(s.get("elapsed", 0))
            key_path  = s.get("key_path") or ""
            key_short = key_path[-22:] if len(key_path) > 22 else key_path
            fmt       = s.get("format", s.get("mode", ""))[:12]
            self._print(
                f"  {s.get('name',''):<16}  {key_short:<22}  "
                f"{s.get('words_tried', 0):>10,}  {elapsed:>8}  "
                f"{fmt:<12}  {s.get('mode','')}"
            )
        self._print(f"{'─' * w}\n")

    # ── GPU / accelerator status ──────────────────────────────────────────────

    def gpu_status(self, devices: list[dict[str, Any]]) -> None:
        """
        Print GPU / accelerator device table.

        Each dict in ``devices`` may contain:
          id, name, vram_mb, temp_c, util_pct, speed, status
        """
        if self.quiet or not devices:
            return

        w = 72
        self._print(f"\n{BOLD}[*]{RESET} GPU Accelerators detected:")
        self._print(f"{'─' * w}")
        self._print(
            f"  {'ID':<3}  {'Device':<28}  {'VRAM':>7}  "
            f"{'Temp':>6}  {'Util':>5}  {'Speed':>12}  Status"
        )
        self._print(f"{'─' * w}")
        for d in devices:
            gid    = str(d.get("id", "?"))
            name   = str(d.get("name", "Unknown"))[:28]
            vram   = f"{d.get('vram_mb', 0):,} MB" if "vram_mb" in d else "  n/a"
            temp   = f"{d.get('temp_c', 0)}°C"     if "temp_c"  in d else " n/a"
            util   = f"{d.get('util_pct', 0)}%"    if "util_pct" in d else "n/a"
            spd    = _fmt_speed(d.get("speed", 0.0))
            status = d.get("status", "idle")
            sc     = C_SUCCESS if status == "active" else C_DIM
            self._print(
                f"  {gid:<3}  {name:<28}  {vram:>7}  "
                f"{temp:>6}  {util:>5}  {BRIGHT_YELLOW}{spd:>12}{RESET}  "
                f"{sc}{status}{RESET}"
            )
        self._print(f"{'─' * w}\n")

    # ── Distributed worker status ─────────────────────────────────────────────

    def worker_status(self, workers: list[dict[str, Any]]) -> None:
        """
        Print distributed worker health panel.

        Each dict may contain:
          id, host, status, speed, tried, last_seen
        """
        if self.quiet or not workers:
            return

        w = 72
        self._print(f"\n{BOLD}[*]{RESET} Distributed Workers ({len(workers)} nodes):")
        self._print(f"{'─' * w}")
        self._print(
            f"  {'ID':<4}  {'Host':<20}  {'Status':<10}  "
            f"{'Speed':>12}  {'Tried':>12}  Last seen"
        )
        self._print(f"{'─' * w}")

        total_speed = 0.0
        for wk in workers:
            wid     = str(wk.get("id", "?"))
            host    = str(wk.get("host", "?"))[:20]
            status  = wk.get("status", "unknown")
            speed   = wk.get("speed", 0.0)
            tried   = wk.get("tried", 0)
            last    = wk.get("last_seen", "")
            total_speed += speed

            if status == "active":
                sc = C_SUCCESS
            elif status in ("idle", "starting"):
                sc = C_WARN
            else:
                sc = C_FAIL

            self._print(
                f"  {wid:<4}  {host:<20}  {sc}{status:<10}{RESET}  "
                f"{C_SPEED}{_fmt_speed(speed):>12}{RESET}  "
                f"{tried:>12,}  {C_DIM}{last}{RESET}"
            )

        self._print(f"{'─' * w}")
        self._print(
            f"  {'TOTAL':>38}  {C_SUCCESS}{_fmt_speed(total_speed):>12}{RESET}"
        )
        self._print(f"{'─' * w}\n")

    # ── Multi-hash hashaxe summary ──────────────────────────────────────────────

    def hashaxe_summary(self, results: list[dict[str, Any]]) -> None:
        """
        Print batch / multi-hash hashaxe result table.

        Each dict may contain:
          hash, hash_type, plaintext (or None), elapsed, tries
        """
        if self.quiet or not results:
            return

        cracked = sum(1 for r in results if r.get("plaintext"))
        w       = 80

        self._print(f"\n{'═' * w}")
        self._print(
            f"  {BOLD}Hashaxe Summary{RESET}  —  "
            f"{C_SUCCESS}{cracked}{RESET}/{len(results)} cracked"
        )
        self._print(f"{'═' * w}")
        self._print(
            f"  {'Hash':<32}  {'Type':<14}  {'Plaintext':<18}  {'Time':>8}"
        )
        self._print(f"{'─' * w}")

        for r in results:
            h      = str(r.get("hash", ""))[:32]
            htype  = str(r.get("hash_type", ""))[:14]
            plain  = r.get("plaintext")
            elap   = r.get("elapsed", 0.0)

            if plain is not None:
                plain_s = f"{C_SUCCESS}{str(plain)[:18]}{RESET}"
            else:
                plain_s = f"{C_DIM}{'<not found>':<18}{RESET}"

            self._print(
                f"  {C_DIM}{h:<32}{RESET}  {C_HASH}{htype:<14}{RESET}  "
                f"{plain_s}  {_fmt_time(elap):>8}"
            )

        self._print(f"{'═' * w}")
        rate = cracked / len(results) * 100 if results else 0
        self._print(
            f"  Success rate : {C_SUCCESS if rate > 50 else C_WARN}{rate:.1f}%{RESET}\n"
        )

    # ── Hash identification panel ─────────────────────────────────────────────

    def hash_id_result(
        self,
        candidates: list[dict[str, Any]],
        raw: str = "",
    ) -> None:
        """
        Print hash identification candidates.

        Each dict may contain:
          name, hashcat_id, john_format, confidence, mitre_id
        """
        if self.quiet or not candidates:
            return

        self._print(f"\n{BOLD}[*]{RESET} Hash identified:")
        if raw:
            self._print(f"    Input : {C_DIM}{raw[:72]}{RESET}")
        self._print(f"{'─' * 70}")
        self._print(
            f"  {'#':<3}  {'Name':<30}  {'Hashcat':>8}  "
            f"{'Confidence':>11}  MITRE"
        )
        self._print(f"{'─' * 70}")

        for i, c in enumerate(candidates[:6], 1):
            conf  = c.get("confidence", 0.0)
            cbar  = "█" * int(conf * 10) + "░" * (10 - int(conf * 10))
            cc    = C_SUCCESS if conf >= 0.8 else (C_WARN if conf >= 0.5 else C_DIM)
            self._print(
                f"  {i:<3}  {str(c.get('name','')):<30}  "
                f"{str(c.get('hashcat_id','')):<8}  "
                f"{cc}{cbar}{RESET} {conf*100:4.0f}%  "
                f"{C_DIM}{c.get('mitre_id','')}{RESET}"
            )

        self._print(f"{'─' * 70}\n")

    # ── AI attack analysis ────────────────────────────────────────────────────

    def ai_analysis(self, result: dict[str, Any]) -> None:
        """
        Print AI attack mode analysis summary.

        ``result`` may contain:
          profile_source, keywords, entropy_score, top_mutations,
          osint_hits, confidence
        """
        if self.quiet:
            return

        self._print(f"\n{BOLD}{BRIGHT_PURPLE}[AI]{RESET} Target analysis complete:")
        src  = result.get("profile_source", "")
        kws  = result.get("keywords", [])
        ent  = result.get("entropy_score", 0.0)
        mut  = result.get("top_mutations", [])
        hits = result.get("osint_hits", 0)
        conf = result.get("confidence", 0.0)

        if src:
            self._print(f"     Source    : {C_KEY}{src}{RESET}")
        if hits:
            self._print(f"     OSINT hits: {C_WARN}{hits}{RESET} unique entries")
        if kws:
            kw_str = ", ".join(str(k) for k in kws[:8])
            self._print(f"     Keywords  : {C_DIM}{kw_str}{RESET}")
        self._print(f"     Entropy   : {YELLOW}{ent:.2f} bits{RESET}")
        self._print(f"     Confidence: {C_SUCCESS if conf > 0.7 else C_WARN}{conf*100:.0f}%{RESET}")
        if mut:
            self._print(f"     Top mutations generated:")
            for m in mut[:5]:
                self._print(f"       {C_DIM}→{RESET} {m}")
        self._print()

    # ── PQC / quantum threat advisory ────────────────────────────────────────

    def pqc_advisory(self, result: dict[str, Any]) -> None:
        """
        Print PQC scanner / HNDL threat advisory.

        ``result`` may contain:
          algorithm, key_bits, quantum_safe, threat_level,
          nist_replacement, harvest_risk
        """
        if self.quiet:
            return

        algo    = result.get("algorithm", "")
        safe    = result.get("quantum_safe", True)
        threat  = result.get("threat_level", "low")
        repl    = result.get("nist_replacement", "")
        harvest = result.get("harvest_risk", "")

        threat_c = C_FAIL if threat == "critical" else (C_WARN if threat == "high" else C_DIM)

        self._print(f"\n{BOLD}[PQC]{RESET} Quantum threat assessment:")
        self._print(f"{'─' * 60}")
        self._print(f"  Algorithm       : {C_HASH}{algo}{RESET}")
        safe_s = f"{C_SUCCESS}YES{RESET}" if safe else f"{C_FAIL}NO — vulnerable to Shor/Grover{RESET}"
        self._print(f"  Quantum-safe    : {safe_s}")
        self._print(f"  Threat level    : {threat_c}{threat.upper()}{RESET}")
        if repl:
            self._print(f"  NIST replacement: {C_SUCCESS}{repl}{RESET}")
        if harvest:
            self._print(f"  Harvest risk    : {C_WARN}{harvest}{RESET}")
        self._print(f"{'─' * 60}\n")

    # ── Logging helpers ───────────────────────────────────────────────────────

    def info(self, msg: str) -> None:
        """General informational message."""
        self._print(f"{BOLD}[*]{RESET} {msg}")

    def ok(self, msg: str) -> None:
        """Success message."""
        self._print(f"{C_SUCCESS}[+]{RESET} {msg}")

    def warn(self, msg: str) -> None:
        """Warning — written to stderr."""
        self._eprint(f"{C_WARN}[!]{RESET} {msg}")

    def error(self, msg: str) -> None:
        """Error — written to stderr."""
        self._eprint(f"{C_FAIL}[!]{RESET} {msg}")

    def debug(self, msg: str) -> None:
        """Verbose-only debug message."""
        if self.verbose and not self.quiet:
            self._print(f"{GREY}[D]{RESET} {C_DIM}{msg}{RESET}")

    # ── Dunder ───────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"Display(verbose={self.verbose!r}, quiet={self.quiet!r}, "
            f"ansi={_USE_ANSI!r})"
        )