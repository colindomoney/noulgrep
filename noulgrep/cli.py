"""noulgrep command line: targets | scan | normalise | summarise | all."""

from __future__ import annotations

import argparse

from . import normalise, scan, summarise, targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noulgrep",
        description="Semgrep runner over deliberately vulnerable target repos (phase 1).",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--target", action="append", metavar="NAME", help="restrict to this target (repeatable)"
    )
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("targets", parents=[common], help="clone/update targets at their pinned SHA")

    s = sub.add_parser("scan", parents=[common], help="run semgrep per target per ruleset")
    s.add_argument(
        "--ruleset", action="append", metavar="NAME", help="restrict to this ruleset (repeatable)"
    )
    s.add_argument("--force", action="store_true", help="re-run even if raw output exists")

    n = sub.add_parser(
        "normalise", parents=[common], help="raw semgrep JSON -> results/findings.jsonl"
    )
    n.add_argument(
        "--context", type=int, default=15, metavar="N", help="lines either side (default 15)"
    )

    sub.add_parser("summarise", parents=[common], help="write and print results/summary.md")

    a = sub.add_parser("all", parents=[common], help="targets, scan, normalise, summarise")
    a.add_argument("--ruleset", action="append", metavar="NAME")
    a.add_argument("--force", action="store_true")
    a.add_argument("--context", type=int, default=15, metavar="N")
    return p


STEPS = {
    "targets": [targets.run],
    "scan": [scan.run],
    "normalise": [normalise.run],
    "summarise": [summarise.run],
    "all": [targets.run, scan.run, normalise.run, summarise.run],
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for step in STEPS[args.command]:
        step(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
