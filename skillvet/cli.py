"""Command-line interface for skillvet."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .scanner import scan_path, render_text, render_markdown, render_json

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="skillvet",
        description="Vet AI agent skills, MCP configs and agent files before you install them.",
    )
    parser.add_argument("--version", action="version", version=f"skillvet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a skill file or directory")
    scan.add_argument("path", help="Path to a SKILL.md, MCP config, script, or a directory")
    scan.add_argument("--format", choices=["text", "md", "json"], default="text",
                      help="Report format (default: text)")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None,
                      help="Exit with code 1 if any finding is at or above this severity (for CI)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        result = scan_path(args.path)
        if args.format == "json":
            sys.stdout.write(render_json(result))
        elif args.format == "md":
            sys.stdout.write(render_markdown(result))
        else:
            sys.stdout.write(render_text(result))

        if args.fail_on:
            threshold = SEVERITY_ORDER[args.fail_on]
            if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in result.findings):
                return 1
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
