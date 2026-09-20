"""Summarise results/manifest.json and results/findings.jsonl into results/summary.md."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime

from .normalise import FINDINGS_PATH
from .scan import COMMON_RULESETS, RESULTS_DIR, last_line, load_manifest
from .targets import ROOT, load_targets

SUMMARY_PATH = RESULTS_DIR / "summary.md"
# Semgrep mixes its old scale (ERROR/WARNING/INFO) with the new one (CRITICAL/HIGH/MEDIUM/LOW);
# columns are whichever appear in the data, in this order, plus anything unexpected at the end.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW", "INFO"]
DVWA_LEVELS = ["low", "medium", "high", "impossible"]


def md_table(headers: list[str], rows: list[list]) -> str:
    def cell(v) -> str:
        return "" if v is None else str(v).replace("|", "\\|")

    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def load_findings() -> list[dict]:
    if not FINDINGS_PATH.exists():
        return []
    with FINDINGS_PATH.open() as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_run_errors(manifest: dict) -> list[dict]:
    """Every Semgrep-internal error from the completed runs' raw files, flattened."""
    rows = []
    for rec in manifest.get("runs", {}).values():
        if rec.get("status") not in ("ok", "partial"):
            continue
        raw = ROOT / rec["raw_path"]
        if not raw.exists():
            continue
        for e in json.loads(raw.read_text()).get("errors") or []:
            t = e.get("type")
            rows.append(
                {
                    "target": rec["target"],
                    "ruleset": rec["ruleset"],
                    "type": str(t[0] if isinstance(t, list) and t else t),
                    "rule_id": e.get("rule_id"),
                    "path": e.get("path"),
                }
            )
    return rows


def severity_columns(findings: list[dict]) -> list[str]:
    seen = {f["severity"] or "?" for f in findings}
    return [s for s in SEVERITY_ORDER if s in seen] + sorted(seen - set(SEVERITY_ORDER))


def section_findings(out: list[str], names: list[str], by_target: dict, findings: list[dict]):
    out.append("\n## Findings per target\n")
    rows = []
    for n in names:
        fs = by_target.get(n, [])
        rows.append(
            [
                n,
                len(fs),
                sum(1 for f in fs if not f["is_vendored"]),
                sum(1 for f in fs if not f["is_vendored"] and not f["is_test_file"]),
                sum(1 for f in fs if f["is_fixture"]),
            ]
        )
    rows.append(["**total**", *[sum(r[i] for r in rows) for i in range(1, 5)]])
    headers = ["target", "total", "excl. vendored", "excl. vendored + test", "in fixture/doc paths"]
    out.append(md_table(headers, rows))

    out.append("\n## Findings per target per severity\n")
    cols = severity_columns(findings)
    sev_rows = []
    for n in names:
        c = Counter(f["severity"] or "?" for f in by_target.get(n, []))
        sev_rows.append([n, *[c.get(s, 0) for s in cols]])
    out.append(md_table(["target", *cols], sev_rows))

    out.append("\n## Top 20 rules overall\n")
    rule_targets: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        rule_targets[f["rule_id"]].add(f["target"])
    top = Counter(f["rule_id"] for f in findings).most_common(20)
    out.append(
        md_table(
            ["rule_id", "count", "targets"],
            [[r, c, ", ".join(sorted(rule_targets[r]))] for r, c in top],
        )
    )

    out.append("\n## Top 10 rules per target\n")
    for n in names:
        c = Counter(f["rule_id"] for f in by_target.get(n, []))
        out.append(f"### {n}\n")
        table = md_table(["rule_id", "count"], [list(x) for x in c.most_common(10)])
        out.append(table if c else "no findings")
        out.append("")


def section_runs(out: list[str], names: list[str], manifest: dict):
    runs = manifest.get("runs", {})
    rulesets = manifest.get("rulesets", {})
    packs = rulesets.get("language_packs", {})
    out.append("## Runs per target per ruleset\n")
    for n in names:
        order = [*rulesets.get("common", COMMON_RULESETS), *packs.get(n, [])]
        rows = []
        total_wall = 0.0
        for rs in order:
            r = runs.get(f"{n}/{rs}")
            if r is None:
                rows.append([rs, "not run", "", "", "", ""])
                continue
            total_wall += r.get("wall_seconds") or 0
            rows.append(
                [
                    rs,
                    r["status"],
                    r.get("findings"),
                    r.get("paths_scanned"),
                    r.get("wall_seconds"),
                    r.get("semgrep_errors"),
                ]
            )
        out.append(f"### {n} ({total_wall:.0f}s total wall clock)\n")
        headers = ["ruleset", "status", "raw findings", "files scanned", "wall s", "semgrep errors"]
        out.append(md_table(headers, rows))
        out.append("")


def section_errors(out: list[str], names: list[str], manifest: dict):
    runs = manifest.get("runs", {})
    out.append("## Errors and timeouts\n")
    bad = [r for r in runs.values() if r["status"] != "ok"]
    if bad:
        out.append("Runs that did not complete normally:\n")
        out.append(
            md_table(
                ["target", "ruleset", "status", "exit", "attempts", "detail"],
                [
                    [
                        r["target"],
                        r["ruleset"],
                        r["status"],
                        r.get("exit_code"),
                        r.get("attempts"),
                        (r.get("error_messages") or [last_line(r.get("stderr_tail"))])[0][:160],
                    ]
                    for r in bad
                ],
            )
        )
    else:
        out.append("No failed, partial or timed-out runs.")

    errors = load_run_errors(manifest)
    if not errors:
        return
    by_type = Counter(e["type"] for e in errors)
    out.append(
        f"\n{len(errors)} Semgrep-internal errors (level warn) inside completed runs. Each one "
        "means a (rule, file) pair was not analysed; the run itself still produced results.\n"
    )
    rows = []
    for t, c in by_type.most_common():
        of_type = [e for e in errors if e["type"] == t]
        rows.append(
            [
                t,
                c,
                len({e["path"] for e in of_type}),
                len({e["rule_id"] for e in of_type if e["rule_id"]}),
                ", ".join(sorted({e["target"] for e in of_type})),
            ]
        )
    out.append(md_table(["type", "count", "files", "rules", "targets"], rows))
    rule_errs = Counter((e["type"], e["rule_id"]) for e in errors if e["rule_id"])
    if rule_errs:
        out.append(
            "\nRules that error most. Where a rule errors on a file it yields no findings there, "
            "so these are blind spots of the community engine, not of the target:\n"
        )
        out.append(
            md_table(
                ["type", "rule_id", "count"],
                [[t, r, c] for (t, r), c in rule_errs.most_common(10)],
            )
        )
    per_target: dict[str, Counter] = defaultdict(Counter)
    for e in errors:
        per_target[e["target"]][e["type"]] += 1
    types = [t for t, _ in by_type.most_common()]
    out.append("\nPer target:\n")
    out.append(
        md_table(
            ["target", *types], [[n, *[per_target[n].get(t, 0) for t in types]] for n in names]
        )
    )


def section_dvwa(out: list[str], by_target: dict):
    out.append("\n## DVWA findings per security level\n")
    out.append(
        "First sanity check of whether Semgrep alone separates `low` (known vulnerable) from "
        "`impossible` (known mitigated). Expectation: it mostly does not.\n"
    )
    dv = by_target.get("dvwa", [])
    levels = [*DVWA_LEVELS, "(none)"]
    lvl = Counter(f["target_meta"].get("security_level", "(none)") for f in dv)
    out.append(md_table(["security_level", "findings"], [[lv, lvl.get(lv, 0)] for lv in levels]))
    pivot: dict[str, Counter] = defaultdict(Counter)
    for f in dv:
        module = f["target_meta"].get("module")
        if module:
            pivot[module][f["target_meta"].get("security_level", "(none)")] += 1
    if pivot:
        out.append("\nPer module (rows) and level (columns):\n")
        out.append(
            md_table(
                ["module", *levels],
                [[m, *[pivot[m].get(lv, 0) for lv in levels]] for m in sorted(pivot)],
            )
        )


def build(manifest: dict, findings: list[dict], targets: list) -> str:
    names = [t.name for t in targets]
    by_target: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_target[f["target"]].append(f)
    runs = manifest.get("runs", {})
    out: list[str] = []
    out.append("# noulgrep phase 1 summary\n")
    out.append(
        f"Generated {datetime.now(UTC).isoformat(timespec='seconds')} with semgrep "
        f"{manifest.get('semgrep', {}).get('version', '?')}: {len(findings)} unique findings "
        f"across {len(by_target)} targets, {len(runs)} scan runs.\n"
    )
    out.append("## Targets\n")
    out.append(
        md_table(
            ["target", "sha", "branch", "languages"],
            [[t.name, t.sha[:12], t.branch, ", ".join(t.languages)] for t in targets],
        )
    )
    section_findings(out, names, by_target, findings)
    section_runs(out, names, manifest)
    section_errors(out, names, manifest)
    section_dvwa(out, by_target)
    return "\n".join(out) + "\n"


def run(args) -> None:
    text = build(load_manifest(), load_findings(), load_targets())
    RESULTS_DIR.mkdir(exist_ok=True)
    SUMMARY_PATH.write_text(text)
    print(text)
    print(f"written to {SUMMARY_PATH.relative_to(ROOT)}")
