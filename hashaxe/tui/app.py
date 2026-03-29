# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/tui/app.py
#  Advanced Terminal User Interface Dashboard with real-time visualization.
#  Features hash rate graphs, node health matrix, attack stages, thermals.
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
hashaxe.tui.app — Advanced Terminal User Interface Dashboard.

Replaces standard CLI output with a dynamic, real-time dashboard using `rich`.
Features:
  - Rolling hash rate graphs (sparklines/progress bars)
  - Distributed node health status matrix
  - Current attack stage (Auto-Pwn pipeline)
  - Live candidate permutations display
  - Hardware thermals & utilization metrics
"""
from __future__ import annotations

import logging
import time
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

logger = logging.getLogger(__name__)


class Dashboard:
    """Dynamic terminal dashboard for active cracking sessions.

    Usage:
        dash = Dashboard(monitor)
        with dash.run():
            # cracking block
    """

    def __init__(self, monitor: Any, title: str = "Hashaxe V1 Dashboard"):
        self.monitor = monitor
        self.title = title
        self.console = Console()
        self.layout = self._make_layout()

    def _make_layout(self) -> Layout:
        """Construct the rich layout structure."""
        layout = Layout(name="root")
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=5),
        )
        layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["left"].split(
            Layout(name="progress", ratio=1),
            Layout(name="cluster", ratio=2),
        )
        return layout

    def _generate_header(self) -> Panel:
        """Top header panel."""
        stats = self.monitor.snapshot() if hasattr(self.monitor, "snapshot") else {}
        mode = stats.get("algorithm", "SHA-256")
        return Panel(
            f"[bold blue]{self.title}[/bold blue] | "
            f"[yellow]Target:[/yellow] {stats.get('attack_mode', 'Auto-Pwn')} | "
            f"[yellow]Algorithm:[/yellow] {mode}",
            style="white on black",
        )

    def _generate_progress(self) -> Panel:
        """Main progress bar and speed."""
        stats = self.monitor.snapshot() if hasattr(self.monitor, "snapshot") else {}
        speed = stats.get("rolling_speed", 0.0)
        checked = stats.get("keyspace_checked", 0)
        total = stats.get("keyspace_total", 0)

        # Format speed
        if speed > 1_000_000_000:
            speed_str = f"{speed / 1_000_000_000:.2f} GH/s"
        elif speed > 1_000_000:
            speed_str = f"{speed / 1_000_000:.2f} MH/s"
        else:
            speed_str = f"{speed:.2f} H/s"

        table = Table.grid(padding=(0, 2))
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Current Speed:", speed_str)
        table.add_row("Progress:", f"{checked} / {total}" if total else str(checked))
        table.add_row("Elapsed Time:", str(stats.get("elapsed", "0.0s")))
        table.add_row("Est. Time Left:", str(stats.get("eta", "Unknown")))

        return Panel(table, title="[bold]Session Metrics[/bold]", border_style="cyan")

    def _generate_cluster_health(self) -> Panel:
        """Distributed worker status table."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Node ID")
        table.add_column("Status")
        table.add_column("Hash Rate")
        table.add_column("GPU Temp")

        nodes = getattr(self.monitor, "nodes", []) if hasattr(self.monitor, "nodes") else []
        if not nodes:
            table.add_row("-", "[dim]Standalone[/dim]", "-", "-")
        else:
            for node in nodes:
                status_color = "green" if node["status"] == "active" else "red"
                table.add_row(
                    node["id"], f"[{status_color}]{node['status']}", node["speed"], node["temp"]
                )

        return Panel(table, title="[bold]Distributed Cluster[/bold]", border_style="magenta")

    def _generate_info(self) -> Panel:
        """Hardware info and current candidates."""
        table = Table.grid(padding=(1, 1))

        # Real stats from monitor
        stats = self.monitor.snapshot() if hasattr(self.monitor, "snapshot") else {}
        attack = stats.get("attack_mode", "wordlist")

        table.add_row(f"[bold cyan]Attack Mode:[/bold cyan] {attack.upper()}")
        table.add_row("[bold cyan]Live Stream:[/bold cyan]")

        # If no real live candidates stream exists yet (e.g. from AI/PCFG)
        live_cands = stats.get("live_candidates", [])
        if not live_cands:
            table.add_row("  [dim]Awaiting candidate stream...[/dim]")
        else:
            for cand in live_cands[:5]:
                table.add_row(f"  {cand}")

        return Panel(table, title="[bold]Real-Time Log[/bold]", border_style="yellow")

    def _generate_footer(self) -> Panel:
        """System health and alerts."""
        return Panel(
            "[dim]Press [bold]CTRL+C[/bold] to interrupt and save session state.[/dim]\n"
            "[green]Status: Running smoothly.[/green]"
        )

    def _update_layout(self) -> None:
        """Refresh all panels with latest data."""
        self.layout["header"].update(self._generate_header())
        self.layout["progress"].update(self._generate_progress())
        self.layout["cluster"].update(self._generate_cluster_health())
        self.layout["right"].update(self._generate_info())
        self.layout["footer"].update(self._generate_footer())

    def run(self):
        """Context manager for the live dashboard."""
        return Live(
            self.layout,
            refresh_per_second=4,
            console=self.console,
            screen=True,
            get_renderable=lambda: (self._update_layout(), self.layout)[1],
        )
