# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/cli.py
#  Command-line interface for HASHAXE password cracker.
#  Handles argument parsing, dispatch, and delegates to cracker.py for logic.
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
cli.py — Command-line interface for hashaxe v2.

All argument parsing and dispatch lives here.
The actual cracking logic is in cracker.py.

Usage:
    hashaxe -k KEY -w WORDLIST [options]
    hashaxe -k KEY --mask '?l?l?l?d?d?d'
    hashaxe -k KEY -w WORDLIST --mask '?d?d?d?d'  # hybrid
    hashaxe -k KEY -w WORDLIST --restore           # resume session
    hashaxe --list-sessions
    hashaxe -k KEY --benchmark
    hashaxe -k KEY --info
"""

from __future__ import annotations

import argparse
import multiprocessing
import sys
from typing import Optional

from hashaxe.cracker import hashaxe
from hashaxe.display import BANNER, Display
from hashaxe.engine import try_passphrase
from hashaxe.rules.mask import MaskEngine
from hashaxe.session import Session


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hashaxe",
        description="SSH Private Key Passphrase Cracker  v1  (GANGA Offensive Ops)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack modes:
  Wordlist     :  hashaxe -k key -w rockyou.txt
  + rules      :  hashaxe -k key -w rockyou.txt --rules
  + rule file  :  hashaxe -k key -w rockyou.txt --rule-file best64.rule
  Mask         :  hashaxe -k key --mask '?l?l?l?d?d?d'
  Hybrid       :  hashaxe -k key -w rockyou.txt --mask '?d?d?d?d'

Examples:
  # Basic wordlist
  hashaxe -k id_ed25519 -w password.txt

  # 16 workers + built-in mutations
  hashaxe -k id_rsa -w rockyou.txt -t 16 --rules

  # Mask attack (3 lowercase + 3 digits)
  hashaxe -k id_ed25519 --mask '?l?l?l?d?d?d'

  # Hybrid: each word + 4-digit suffix
  hashaxe -k id_rsa -w rockyou.txt --mask '?d?d?d?d'

  # Resume an interrupted session
  hashaxe -k id_ed25519 -w rockyou.txt --restore

  # Benchmark this key
  hashaxe -k id_ed25519 --benchmark

  # Hashaxe + verify via live SSH
  hashaxe -k id_ed25519 -w rockyou.txt \\
      --verify-host 127.0.0.1 --verify-port 2222 --verify-user svc_user@domain.vl

  # GPU-accelerated (auto-detected, NVIDIA/AMD)
  hashaxe -k id_ed25519 -w rockyou.txt

  # Distributed master (other machines connect as workers)
  hashaxe -k id_ed25519 -w rockyou.txt --distributed-master

  # Distributed worker (connect to master at 192.168.1.10)
  hashaxe --distributed-worker --master 192.168.1.10

  # Show GPU info
  hashaxe -k id_ed25519 --gpu-info
        """,
    )

    # ── Key / wordlist ─────────────────────────────────────────────────────────
    p.add_argument(
        "-k",
        "--key",
        required=False,
        default=None,
        metavar="FILE",
        help="Path to encrypted file (SSH key, ZIP, PDF, or any supported format)",
    )
    p.add_argument(
        "--hash",
        metavar="HASH",
        default=None,
        help="Inline hash string to hashaxe (e.g. MD5, SHA-256, bcrypt, shadow line)",
    )
    p.add_argument(
        "--format",
        metavar="FMT",
        default=None,
        dest="format_override",
        help=(
            "Force a specific format (overrides auto-detection).\n"
            "  Examples: hash.md5, hash.sha256, hash.bcrypt, ssh.openssh, ssh.ppk"
        ),
    )
    p.add_argument(
        "-w",
        "--wordlist",
        metavar="FILE",
        default=None,
        help="Path to wordlist (use '-' for stdin).  Not needed for mask-only attacks.",
    )

    # ── Workers ────────────────────────────────────────────────────────────────
    p.add_argument(
        "-t",
        "--threads",
        type=int,
        default=0,
        metavar="N",
        help=f"Parallel worker processes (default: auto = {multiprocessing.cpu_count()} CPUs)",
    )

    # ── Mutation rules ─────────────────────────────────────────────────────────
    p.add_argument(
        "--rules",
        action="store_true",
        help="Apply built-in mutation rules to each word (capitalize, l33t, suffixes…)",
    )
    p.add_argument(
        "--rule-file",
        metavar="FILE",
        help="Path to Hashcat .rule file (e.g. best64.rule, OneRuleToRuleThemAll.rule)",
    )

    # ── Mask attack ────────────────────────────────────────────────────────────
    p.add_argument(
        "--mask",
        metavar="MASK",
        help=(
            "Hashcat-style mask for brute-force or hybrid attacks.\n"
            "  Tokens: ?l=lower ?u=upper ?d=digit ?s=special ?a=all\n"
            "  Example: '?u?l?l?l?d?d?d'  or  'Pass?d?d?d?d'"
        ),
    )
    p.add_argument(
        "-1",
        "--custom-charset1",
        metavar="CS",
        dest="cs1",
        help="Custom charset for ?1 (e.g. 'abc123')",
    )
    p.add_argument(
        "-2", "--custom-charset2", metavar="CS", dest="cs2", help="Custom charset for ?2"
    )
    p.add_argument(
        "-3", "--custom-charset3", metavar="CS", dest="cs3", help="Custom charset for ?3"
    )
    p.add_argument(
        "-4", "--custom-charset4", metavar="CS", dest="cs4", help="Custom charset for ?4"
    )

    # ── Advanced attack modes ─────────────────────────────────────────────────
    p.add_argument(
        "--attack",
        metavar="MODE",
        choices=[
            "wordlist",
            "mask",
            "combinator",
            "prince",
            "markov",
            "hybrid",
            "policy",
            "osint",
            "pcfg",
        ],
        default=None,
        help=(
            "Attack mode: wordlist, mask, combinator, prince, markov, hybrid, policy, osint, pcfg.\n"
            "  Default: auto (wordlist if -w given, mask if --mask given)"
        ),
    )
    p.add_argument(
        "--auto-pwn", action="store_true", help="Run intelligent Auto-Pwn orchestration pipeline"
    )
    p.add_argument(
        "--wordlist2", metavar="FILE", default=None, help="Second wordlist for combinator attack"
    )
    p.add_argument(
        "--policy",
        metavar="RULES",
        default=None,
        help=(
            "Password policy constraints for policy attack.\n"
            "  Example: 'len>=8,upper,digit,symbol'"
        ),
    )
    p.add_argument(
        "--markov-order",
        metavar="N",
        type=int,
        default=3,
        help="Markov chain order (1–6, default: 3)",
    )
    p.add_argument(
        "--prince-min",
        metavar="N",
        type=int,
        default=1,
        help="PRINCE minimum chain elements (default: 1)",
    )
    p.add_argument(
        "--prince-max",
        metavar="N",
        type=int,
        default=4,
        help="PRINCE maximum chain elements (default: 4)",
    )

    # ── AI generation ─────────────────────────────────────────────────────────
    p.add_argument(
        "--ai",
        action="store_true",
        default=False,
        help="Enable AI-powered candidate generation (GPT-2 + Markov fallback)",
    )
    p.add_argument(
        "--candidates",
        type=int,
        default=1000,
        metavar="N",
        dest="ai_candidates",
        help="Number of AI-generated candidates per seed (default: 1000)",
    )
    p.add_argument(
        "--download-models",
        action="store_true",
        default=False,
        dest="download_models",
        help="Download and cache AI models (GPT-2) for offline use",
    )

    # ── OSINT profiling ────────────────────────────────────────────────────────
    p.add_argument(
        "--osint-file",
        metavar="FILE",
        default=None,
        dest="osint_file",
        help=(
            "OSINT intelligence source file (tweets, bio, social media dump).\n"
            "  Extracts names, dates, emails, keywords and generates targeted candidates.\n"
            "  Automatically sets --attack osint."
        ),
    )
    p.add_argument(
        "--osint-export",
        metavar="FILE",
        default=None,
        dest="osint_export",
        help="Export OSINT-generated wordlist to file (without cracking)",
    )

    # ── Output ─────────────────────────────────────────────────────────────────
    p.add_argument("-o", "--output", metavar="FILE", help="Save cracked passphrase to file")
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output: per-worker stats instead of progress bar",
    )
    p.add_argument(
        "--version", action="version", version="%(prog)s 2.0.0"
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress all output except the passphrase itself",
    )
    p.add_argument(
        "--tui", action="store_true", help="Use advanced real-time Terminal UI dashboard"
    )

    # ── Session management ─────────────────────────────────────────────────────
    p.add_argument(
        "--restore",
        action="store_true",
        help="Resume a previously interrupted session (auto-detects by key+wordlist)",
    )
    p.add_argument(
        "--session",
        metavar="NAME",
        dest="session_name",
        help="Named session (overrides auto-generated name)",
    )
    p.add_argument("--list-sessions", action="store_true", help="List all saved sessions and exit")
    p.add_argument("--delete-session", metavar="NAME", help="Delete a named session and exit")

    # ── SSH verify ─────────────────────────────────────────────────────────────
    p.add_argument(
        "--verify-host", metavar="HOST", help="SSH host to test the cracked passphrase against"
    )
    p.add_argument(
        "--verify-port", type=int, default=22, metavar="PORT", help="SSH port (default: 22)"
    )
    p.add_argument("--verify-user", metavar="USER", help="SSH username for live verification")

    # ── Utility modes ──────────────────────────────────────────────────────────
    p.add_argument(
        "--info", action="store_true", help="Display key metadata and exit (no cracking)"
    )
    p.add_argument(
        "--benchmark",
        action="store_true",
        help="Benchmark passphrase testing speed for this key and exit",
    )
    p.add_argument(
        "--estimate",
        metavar="WORDS",
        type=int,
        help="Estimate hashaxe time for N wordlist entries and exit",
    )
    p.add_argument(
        "--api-server",
        action="store_true",
        help="Launch headless REST API server for C2 integration",
    )
    p.add_argument(
        "--api-port",
        type=int,
        default=8080,
        metavar="PORT",
        help="Port for the API server (default: 8080)",
    )

    # ── GPU acceleration ───────────────────────────────────────────────────────
    p.add_argument(
        "--gpu",
        action="store_true",
        help="Enable GPU acceleration (default behavior, flag provided for compatibility)",
    )
    p.add_argument(
        "--no-gpu",
        action="store_true",
        help="Disable GPU acceleration (use CPU-only multiprocessing)",
    )
    p.add_argument("--gpu-info", action="store_true", help="Display detected GPU info and exit")

    # ── Distributed cracking ───────────────────────────────────────────────────
    p.add_argument(
        "--distributed-master",
        action="store_true",
        help="Run as distributed master node (dispatches work to workers)",
    )
    p.add_argument(
        "--distributed-worker",
        action="store_true",
        help="Run as distributed worker node (receives work from master)",
    )
    p.add_argument(
        "--master",
        metavar="HOST",
        dest="master_host",
        help="Master node hostname/IP (required for --distributed-worker)",
    )
    p.add_argument(
        "--work-port",
        type=int,
        default=5555,
        metavar="PORT",
        help="ZMQ work dispatch port (default: 5555)",
    )
    p.add_argument(
        "--result-port",
        type=int,
        default=5556,
        metavar="PORT",
        help="ZMQ result collection port (default: 5556)",
    )
    p.add_argument(
        "--no-smart-order", action="store_true", help="Disable frequency-based candidate reordering"
    )

    # ── Results database ───────────────────────────────────────────────────────
    p.add_argument(
        "--show-results",
        action="store_true",
        help="Show all cracked results from the database and exit",
    )
    p.add_argument(
        "--stats", action="store_true", help="Show aggregate cracking statistics and exit"
    )
    p.add_argument(
        "--export-results",
        metavar="FILE",
        help="Export results to file (.json or .csv based on extension)",
    )
    p.add_argument(
        "--clear-results",
        action="store_true",
        help="Delete all saved hashaxe results (DESTRUCTIVE)",
    )
    p.add_argument(
        "--filter-format",
        metavar="FMT",
        help="Filter results by format ID (used with --show-results/--export-results)",
    )

    return p


def main() -> None:
    multiprocessing.freeze_support()

    parser = _build_parser()
    args = parser.parse_args()
    disp = Display(verbose=args.verbose, quiet=args.quiet)

    # ── --list-sessions ────────────────────────────────────────────────────────
    if args.list_sessions:
        disp.banner()
        disp.session_list(Session.list_sessions())
        sys.exit(0)

    # ── --delete-session ───────────────────────────────────────────────────────
    if args.delete_session:
        Session().delete(args.delete_session)
        disp.ok(f"Session '{args.delete_session}' deleted.")
        sys.exit(0)

    # ── --show-results ────────────────────────────────────────────────────────
    if args.show_results:
        disp.banner()
        from hashaxe.db import CrackDB

        db = CrackDB()
        rows = db.query(format_id=args.filter_format, limit=100)
        print(db.format_results_table(rows))
        sys.exit(0)

    # ── --stats ───────────────────────────────────────────────────────────────
    if args.stats:
        disp.banner()
        from hashaxe.db import CrackDB

        db = CrackDB()
        print(db.format_stats())
        sys.exit(0)

    # ── --export-results ──────────────────────────────────────────────────────
    if args.export_results:
        from hashaxe.db import CrackDB

        db = CrackDB()
        outpath = args.export_results
        fmt = "csv" if outpath.endswith(".csv") else "json"
        db.export(fmt=fmt, path=outpath, format_id=args.filter_format)
        disp.ok(f"Results exported to {outpath}")
        sys.exit(0)

    # ── --clear-results ───────────────────────────────────────────────────────
    if args.clear_results:
        from hashaxe.db import CrackDB

        db = CrackDB()
        deleted = db.clear_all()
        disp.ok(f"Deleted {deleted} result(s) from database.")
        sys.exit(0)

    # ── --api-server ───────────────────────────────────────────────────────────
    if args.api_server:
        disp.banner()
        try:
            import uvicorn

            from hashaxe.api import app

            disp.ok(f"Starting Hashaxe REST API on port {args.api_port}...")
            uvicorn.run(app, host="127.0.0.1", port=args.api_port, log_level="info")
            # NOTE: Use --api-host 0.0.0.0 explicitly to expose on all interfaces
        except ImportError:
            disp.error("Failed to start API server. Is 'uvicorn' installed?")
            sys.exit(1)
        sys.exit(0)

    # ── --info ─────────────────────────────────────────────────────────────────
    if args.info:
        if not args.key and not args.hash:
            parser.error("--info requires --key / -k or --hash")
        disp.banner()
        try:
            from pathlib import Path

            from hashaxe.formats import FormatRegistry

            registry = FormatRegistry()
            data = Path(args.key).read_bytes() if args.key else args.hash.encode("utf-8")
            p = Path(args.key) if args.key else None

            match = registry.identify(data, p)
            if not match:
                raise ValueError("Unrecognised format")
            target = match.handler.parse(data, p)
            print(f"{'─'*50}")
            print(f"  File      : {args.key if args.key else 'inline (--hash)'}")
            print(f"  Format    : {target.format_id}")
            print(f"  Encrypted : {target.is_encrypted}")
            for k, v in match.handler.display_info(target).items():
                print(f"  {k:<10}: {v}")
            print(f"{'─'*50}")
        except Exception as exc:
            disp.error(str(exc))
            sys.exit(1)
        sys.exit(0)

    # ── --download-models ──────────────────────────────────────────────────────
    if args.download_models:
        disp.banner()
        from hashaxe.ai.model_manager import ModelManager

        mgr = ModelManager()
        if mgr.download(force=True):
            sys.exit(0)
        else:
            sys.exit(1)

    # ── --gpu-info ─────────────────────────────────────────────────────────────
    if args.gpu_info:
        disp.banner()
        try:
            from hashaxe.gpu.accelerator import detect_gpu, gpu_info_string

            device = detect_gpu()
            print(f"  {gpu_info_string(device)}")
        except Exception as exc:
            print(f"  GPU probe error: {exc}")
        sys.exit(0)

    # ── --osint-export (export OSINT wordlist without cracking) ────────────────
    if args.osint_export:
        if not args.osint_file:
            parser.error("--osint-export requires --osint-file")
        disp.banner()
        try:
            from hashaxe.osint import OsintProfiler

            profiler = OsintProfiler()
            profiler.load_file(args.osint_file)
            count = profiler.export(args.osint_export)
            disp.ok(f"OSINT wordlist exported: {count:,} candidates → {args.osint_export}")
        except Exception as exc:
            disp.error(f"OSINT export failed: {exc}")
            sys.exit(1)
        sys.exit(0)

    # ── --estimate ─────────────────────────────────────────────────────────────
    if args.estimate:
        disp.banner()
        try:
            from pathlib import Path

            from hashaxe.formats import FormatRegistry

            registry = FormatRegistry()
            data = Path(args.key).read_bytes() if args.key else args.hash.encode("utf-8")
            p = Path(args.key) if args.key else None
            match = registry.identify(data, p)
            if not match:
                raise ValueError("Unrecognised format")
            target = match.handler.parse(data, p)
        except Exception as exc:
            disp.error(str(exc))
            sys.exit(1)
        cpu = multiprocessing.cpu_count()
        n = args.threads if args.threads > 0 else cpu
        from hashaxe.cracker import benchmark as do_bench

        speed_core = do_bench(target, match.handler, disp, n)
        total_speed = speed_core * n
        words = args.estimate
        secs = words / total_speed if total_speed > 0 else float("inf")
        print(f"\n  Estimate for {words:,} words @ {total_speed:.1f} pw/s:")
        if secs < 60:
            print(f"    ~{secs:.1f} seconds")
        elif secs < 3600:
            print(f"    ~{secs/60:.1f} minutes")
        elif secs < 86400:
            print(f"    ~{secs/3600:.1f} hours")
        else:
            print(f"    ~{secs/86400:.1f} days")
        sys.exit(0)

    # ── Require --key or --hash for all other modes ───────────────────────────
    if not args.key and not args.hash:
        parser.error("--key / -k or --hash is required for this operation")

    # ── Auto-info fallback: if user provides --hash/--key but no attack mode, ──
    # ── show info automatically instead of erroring.                           ──
    # NOTE: We must run the info logic HERE (not just set args.info = True)
    # because the `if args.info:` handler at line ~527 has already been skipped.
    if (
        not args.wordlist
        and not args.mask
        and not args.benchmark
        and not args.ai
        and not args.osint_file
    ):
        disp.banner()
        try:
            from pathlib import Path

            from hashaxe.formats import FormatRegistry

            registry = FormatRegistry()
            data = Path(args.key).read_bytes() if args.key else args.hash.encode("utf-8")
            p = Path(args.key) if args.key else None

            match = registry.identify(data, p)
            if not match:
                raise ValueError("Unrecognised format")
            target = match.handler.parse(data, p)
            print(f"{'─'*50}")
            print(f"  File      : {args.key if args.key else 'inline (--hash)'}")
            print(f"  Format    : {target.format_id}")
            print(f"  Encrypted : {target.is_encrypted}")
            for k, v in match.handler.display_info(target).items():
                print(f"  {k:<10}: {v}")
            print(f"{'─'*50}")
        except Exception as exc:
            disp.error(str(exc))
            sys.exit(1)
        sys.exit(0)

    # ── Early validation for attack modes requiring wordlist ──────────────────
    if args.attack == "pcfg" and not args.wordlist:
        parser.error(
            "PCFG attack requires a wordlist for grammar training.\n"
            "  Usage: hashaxe --hash HASH -w WORDLIST --attack pcfg"
        )
    if args.ai and not args.wordlist:
        try:
            import torch
            import transformers
        except ImportError:
            parser.error(
                "AI mode requires either:\n"
                "  (1) transformers + torch installed (for GPT-2 generation), OR\n"
                "  (2) --wordlist / -w for Markov chain fallback\n"
                "  Usage: hashaxe --hash HASH -w WORDLIST --ai"
            )
    if args.attack == "combinator" and not args.wordlist2:
        parser.error(
            "Combinator attack requires a second wordlist.\n"
            "  Usage: hashaxe --hash HASH -w WORDLIST --wordlist2 WORDLIST2 --attack combinator"
        )

    # ── OSINT auto-configuration ──────────────────────────────────────────────
    if args.osint_file:
        args.attack = "osint"
        if not args.wordlist:
            args.wordlist = args.osint_file  # OSINT source passed via wordlist field

    # ── Distributed mode validation ───────────────────────────────────────────
    if args.distributed_master:
        if not args.wordlist and not args.mask:
            parser.error(
                "Distributed master requires --wordlist or --mask.\n"
                "  Usage: hashaxe -k KEY -w WORDLIST --distributed-master"
            )

    # ── Auto-Pwn Orchestration ────────────────────────────────────────────────
    if args.auto_pwn:
        from hashaxe.auto_pwn import AutoPwnOrchestrator

        orchestrator = AutoPwnOrchestrator(
            key_path=args.key,
            wordlist_path=args.wordlist or "",
            osint_path=args.osint_file,
            threads=args.threads,
            raw_hash=args.hash,
        )
        passphrase = orchestrator.execute_pipeline()
        if passphrase:
            disp.ok(f"AUTO-PWN SUCCESS! Passphrase: {passphrase}")
        else:
            disp.error("Auto-Pwn exhausted all pipelines. Target not cracked.")
        sys.exit(0 if passphrase else 1)

    # ── Build custom charset dict ──────────────────────────────────────────────
    custom_charsets: dict[str, str] = {}
    if args.cs1:
        custom_charsets["?1"] = args.cs1
    if args.cs2:
        custom_charsets["?2"] = args.cs2
    if args.cs3:
        custom_charsets["?3"] = args.cs3
    if args.cs4:
        custom_charsets["?4"] = args.cs4

    # ── Dispatch to hashaxe() ────────────────────────────────────────────────────
    passphrase = hashaxe(
        key_path=args.key,
        raw_hash=args.hash,
        wordlist=args.wordlist or "",
        threads=args.threads,
        use_rules=args.rules,
        rule_file=args.rule_file,
        mask=args.mask,
        custom_charsets=custom_charsets or None,
        verbose=args.verbose,
        quiet=args.quiet,
        output=args.output,
        session_name=args.session_name,
        restore=args.restore,
        do_benchmark=args.benchmark,
        use_gpu=not args.no_gpu,
        use_smart_order=not args.no_smart_order,
        distributed_master=args.distributed_master,
        distributed_worker=args.distributed_worker,
        master_host=args.master_host,
        verify_host=args.verify_host,
        verify_port=args.verify_port,
        verify_user=args.verify_user,
        attack_mode_override="ai" if args.ai else args.attack,
        wordlist2=args.wordlist2,
        policy=args.policy,
        markov_order=args.markov_order,
        prince_min=args.prince_min,
        prince_max=args.prince_max,
        use_tui=args.tui,
        ai_candidates=args.ai_candidates,
        format_override=args.format_override,
    )

    # Quiet mode: just print the passphrase
    if args.quiet and passphrase is not None:
        print(passphrase)

    sys.exit(0 if passphrase is not None or args.benchmark else 1)


if __name__ == "__main__":
    main()
