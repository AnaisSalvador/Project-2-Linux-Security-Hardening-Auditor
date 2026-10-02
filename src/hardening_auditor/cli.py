"""Command-line interface for the Linux Security Hardening Auditor."""

import argparse
import platform
from pathlib import Path

from hardening_auditor.checks.registry import get_all_checks
from hardening_auditor.reporting.console import render_console
from hardening_auditor.reporting.json_report import render_json
from hardening_auditor.reporting.markdown import render_markdown
from hardening_auditor.runner import Runner
from hardening_auditor.system import SystemInfo


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Run a read-only Linux security hardening audit."
        )
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory where JSON and Markdown reports are written.",
    )

    return parser


def main() -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if platform.system() != "Linux":
        parser.error(
            "This auditor must be executed on Linux. "
            "Use the Kali Linux VM or another Linux system."
        )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    system = SystemInfo()
    checks = get_all_checks()

    report = Runner(system, checks).run()

    print(render_console(report))

    json_path = output_dir / "audit.json"
    markdown_path = output_dir / "audit.md"

    json_path.write_text(
        render_json(report),
        encoding="utf-8",
    )

    markdown_path.write_text(
        render_markdown(report),
        encoding="utf-8",
    )

    print()
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")

    return 0
