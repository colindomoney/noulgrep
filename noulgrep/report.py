"""Policy and evaluation over results/triaged-*.jsonl -> results/report.md.

Policy, thresholds set from the DVWA labelled sample on 2026-09-20 (model jev-1.13.0,
questions v1, path-redacted state: P(tp) >= 0.8 gave precision 0.98 / recall 0.84, AUC 0.87):
  report   P(true_positive) >= ACT_P_TP, ranked by P(tp) x (1 + exploitability)
  suppress P(false_positive) >= SUPPRESS_P_FP (logged, never deleted)
  review   everything else, including needs_context
Deterministic flags win over the model: vendored findings are dropped, test-file findings are
kept but shown separately.

Evaluation uses ground_truth/<target>.yaml: a finding whose line range overlaps a `vulns`
location is a known true positive; one that overlaps a `controls` entry (DVWA impossible.php)
is a known false positive. Everything else is unlabelled and stays out of precision/recall.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from .classify import triaged_path
from .ground_truth import CATEGORIES, GROUND_TRUTH_DIR
from .ground_truth import load as load_ground_truth
from .normalise import FINDINGS_PATH
from .questions import MODEL, QUESTIONS_VERSION
from .scan import RESULTS_DIR, log
from .summarise import md_table
from .targets import ROOT, load_targets

REPORT_PATH = RESULTS_DIR / "report.md"
ACT_P_TP = 0.80  # re-derive if MODEL or QUESTIONS_VERSION changes
SUPPRESS_P_FP = 0.80
P_TP_THRESHOLDS = (0.5, 0.6, 0.7, 0.8, 0.9)


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.open() if line.strip()]


# --- labelling against ground truth -----------------------------------------------------------


def overlaps(f: dict, path: str, lines: list[int]) -> bool:
    return f["path"] == path and not (f["end_line"] < lines[0] or f["start_line"] > lines[1])


def label_findings(findings: list[dict], gt: dict | None) -> dict[str, dict]:
    """finding_id -> {"label": tp|fp|None, "vuln_id", "category"}."""
    out = {f["finding_id"]: {"label": None, "vuln_id": None, "category": None} for f in findings}
    if not gt:
        return out
    for f in findings:
        for v in gt.get("vulns", []):
            if any(overlaps(f, loc["path"], loc["lines"]) for loc in v["locations"]):
                out[f["finding_id"]] = {
                    "label": "tp",
                    "vuln_id": v["id"],
                    "category": v["category"],
                }
                break
        else:
            for c in gt.get("controls", []):
                if overlaps(f, c["path"], c["lines"]):
                    out[f["finding_id"]] = {"label": "fp", "vuln_id": c["id"], "category": None}
                    break
    return out


def gt_coverage(findings: list[dict], gt: dict) -> tuple[int, int, list[str]]:
    """How many ground-truth locations (in scanned paths) got at least one Semgrep finding."""
    total = hit = 0
    missed = []
    for v in gt.get("vulns", []):
        for loc in v["locations"]:
            if loc.get("scanned") is False:
                continue
            total += 1
            if any(overlaps(f, loc["path"], loc["lines"]) for f in findings):
                hit += 1
            else:
                missed.append(f"{v['id']} {loc['path']}:{loc['lines'][0]}-{loc['lines'][1]}")
    return hit, total, missed


# --- policy -------------------------------------------------------------------------------------


def bucket(f: dict, t: dict) -> str:
    if f["is_vendored"]:
        return "dropped_vendored"
    p = t["answers"]["verdict"]["probabilities"]
    if p["true_positive"] >= ACT_P_TP:
        return "report"
    if p["false_positive"] >= SUPPRESS_P_FP:
        return "suppress"
    return "review"


def rank_key(f: dict, t: dict) -> float:
    a = t["answers"]
    return a["verdict"]["probabilities"]["true_positive"] * (1 + a["exploitability"]["score"])


# --- metrics --------------------------------------------------------------------------------------


def pr_at(labelled: list[tuple[str, float]], thr: float) -> tuple[float, float, int, int]:
    """labelled = [(label, p_tp)]; returns precision, recall, n_pred_pos, n_pos at threshold."""
    pos = sum(1 for lab, _ in labelled if lab == "tp")
    pred = [(lab, p) for lab, p in labelled if p >= thr]
    tp = sum(1 for lab, _ in pred if lab == "tp")
    precision = tp / len(pred) if pred else float("nan")
    recall = tp / pos if pos else float("nan")
    return precision, recall, len(pred), pos


def auc(labelled: list[tuple[str, float]]) -> float | None:
    """Probability a random known-tp scores above a random known-fp (Mann-Whitney)."""
    pos = [p for lab, p in labelled if lab == "tp"]
    neg = [p for lab, p in labelled if lab == "fp"]
    if not pos or not neg:
        return None
    wins = sum((1.0 if p > n else 0.5 if p == n else 0.0) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def fmt(x) -> str:
    return "" if x is None or x != x else f"{x:.2f}"


# --- report ---------------------------------------------------------------------------------------


def section_policy(out: list[str], names: list[str], F: dict, T: dict) -> None:
    out.append("## Policy buckets per target\n")
    out.append(
        f"Report at P(true_positive) >= {ACT_P_TP}, suppress at P(false_positive) >= "
        f"{SUPPRESS_P_FP}, review otherwise. Thresholds from the DVWA labelled sample for "
        f"`{MODEL}` / questions `{QUESTIONS_VERSION}`.\n"
    )
    cols = ["report", "review", "suppress", "dropped_vendored"]
    rows = []
    for n in names:
        c = Counter(bucket(F[i], T[i]) for i in T if T[i]["target"] == n)
        rows.append([n, sum(c.values()), *[c.get(k, 0) for k in cols]])
    rows.append(["**total**", *[sum(r[i] for r in rows) for i in range(1, len(cols) + 2)]])
    out.append(md_table(["target", "triaged", *cols], rows))


def section_ranked(out: list[str], F: dict, T: dict, labels: dict, top: int = 25) -> None:
    out.append(
        f"\n## Top {top} reported findings, ranked by P(true_positive) x (1 + exploitability)\n"
    )
    ids = [i for i in T if bucket(F[i], T[i]) == "report"]
    ids.sort(key=lambda i: -rank_key(F[i], T[i]))
    rows = []
    for i in ids[:top]:
        a = T[i]["answers"]
        rows.append(
            [
                F[i]["target"],
                f"{F[i]['path']}:{F[i]['start_line']}",
                F[i]["rule_id"].rsplit(".", 1)[-1][:40],
                fmt(a["verdict"]["probabilities"]["true_positive"]),
                fmt(a["exploitability"]["score"]),
                a["vuln_class"]["choice"],
                labels[i]["label"] or "",
                "test" if F[i]["is_test_file"] else "fixture" if F[i]["is_fixture"] else "",
            ]
        )
    out.append(
        md_table(["target", "location", "rule", "P(tp)", "exploit", "class", "gt", "flag"], rows)
    )


def section_suppressed(out: list[str], F: dict, T: dict) -> None:
    out.append("\n## Suppressed: rules Jev rejects at high confidence\n")
    sup = [i for i in T if bucket(F[i], T[i]) == "suppress"]
    c = Counter(F[i]["rule_id"] for i in sup)
    out.append(
        md_table(
            ["rule_id", "suppressed", "of total"],
            [[r, n, sum(1 for i in T if F[i]["rule_id"] == r)] for r, n in c.most_common(15)],
        )
    )
    out.append("\n## Review queue: rules that most often land in the middle band\n")
    rev = [i for i in T if bucket(F[i], T[i]) == "review"]
    c = Counter(F[i]["rule_id"] for i in rev)
    out.append(
        md_table(
            ["rule_id", "in review", "of total"],
            [[r, n, sum(1 for i in T if F[i]["rule_id"] == r)] for r, n in c.most_common(15)],
        )
    )


def section_eval(
    out: list[str],
    name: str,
    F: dict,
    T: dict,
    R: dict,
    labels: dict,
    gt: dict,
    findings: list[dict],
) -> None:
    out.append(f"\n## Evaluation: {name}\n")
    hit, total, missed = gt_coverage(findings, gt)
    out.append(
        f"Semgrep coverage of ground truth: **{hit}/{total}** labelled locations have at least one "
        "finding. This bounds recall for everything downstream: Jev cannot rank what Semgrep "
        "did not report.\n"
    )
    if missed:
        out.append(
            "Missed by Semgrep: "
            + ", ".join(f"`{m}`" for m in missed[:20])
            + (" ..." if len(missed) > 20 else "")
            + "\n"
        )
    ids = [i for i in T if T[i]["target"] == name and labels[i]["label"]]
    n_tp = sum(1 for i in ids if labels[i]["label"] == "tp")
    n_fp = sum(1 for i in ids if labels[i]["label"] == "fp")
    out.append(
        f"Labelled findings: {n_tp} known true positives, {n_fp} known false positives "
        "(controls).\n"
    )
    if not ids:
        return
    if not n_fp:
        out.append(
            "No known false positives for this target, so precision below is trivially 1.0 and "
            "only recall (how many known vulnerabilities clear the threshold) is informative.\n"
        )
    for variant, S in (("full", T), ("redacted path", R)):
        lab = [
            (labels[i]["label"], S[i]["answers"]["verdict"]["probabilities"]["true_positive"])
            for i in ids
            if i in S
        ]
        if not lab:
            continue
        a = auc(lab)
        out.append(f"### verdict, {variant} state{f' (AUC {a:.2f})' if a is not None else ''}\n")
        rows = []
        for thr in P_TP_THRESHOLDS:
            p, r, npred, npos = pr_at(lab, thr)
            rows.append([f"P(tp) >= {thr}", fmt(p), fmt(r), npred, npos])
        out.append(
            md_table(
                ["threshold", "precision", "recall", "predicted positive", "known positive"], rows
            )
        )
        mean_tp = [p for lab_, p in lab if lab_ == "tp"]
        mean_fp = [p for lab_, p in lab if lab_ == "fp"]
        line = f"Mean P(tp): known-tp {sum(mean_tp) / len(mean_tp):.2f}" if mean_tp else ""
        if mean_fp:
            line += f", known-fp {sum(mean_fp) / len(mean_fp):.2f}"
        out.append(line + "\n")
    # class confusion on known true positives
    tp_ids = [i for i in ids if labels[i]["label"] == "tp"]
    if tp_ids:
        cats = [c for c in CATEGORIES if any(labels[i]["category"] == c for i in tp_ids)]
        preds = [
            c
            for c in CATEGORIES
            if any(T[i]["answers"]["vuln_class"]["choice"] == c for i in tp_ids)
        ]
        m = defaultdict(Counter)
        for i in tp_ids:
            m[labels[i]["category"]][T[i]["answers"]["vuln_class"]["choice"]] += 1
        agree = sum(m[c][c] for c in cats) / len(tp_ids)
        out.append(
            "### vuln_class on known true positives (rows = ground truth, cols = Jev), "
            f"agreement {agree:.2f}\n"
        )
        out.append(
            md_table(["gt \\ jev", *preds], [[c, *[m[c].get(p, 0) for p in preds]] for c in cats])
        )
    # disagreements
    out.append("\n### Disagreements to inspect by hand\n")
    rows = []
    for i in ids:
        p = T[i]["answers"]["verdict"]["probabilities"]["true_positive"]
        lab = labels[i]["label"]
        if (lab == "tp" and p < 0.5) or (lab == "fp" and p >= 0.5):
            rows.append(
                [
                    lab,
                    fmt(p),
                    f"{F[i]['path']}:{F[i]['start_line']}",
                    F[i]["rule_id"].rsplit(".", 1)[-1][:40],
                    labels[i]["vuln_id"],
                ]
            )
    rows.sort(key=lambda r: (r[0], r[1]))
    out.append(md_table(["gt", "P(tp)", "location", "rule", "gt id"], rows) if rows else "None.")


def build() -> str:
    targets = load_targets()
    names = [t.name for t in targets]
    findings = load_jsonl(FINDINGS_PATH)
    F = {f["finding_id"]: f for f in findings}
    T = {r["finding_id"]: r for r in load_jsonl(triaged_path("full")) if not r.get("error")}
    R = {r["finding_id"]: r for r in load_jsonl(triaged_path("redacted")) if not r.get("error")}
    T = {i: r for i, r in T.items() if i in F}
    gts = {}
    for n in names:
        path = GROUND_TRUTH_DIR / f"{n}.yaml"
        if path.exists():
            try:
                doc = load_ground_truth(n)
                if doc.get("vulns"):
                    gts[n] = doc
            except ValueError as e:
                log(f"ground truth skipped: {e}")
    labels = {}
    for n in names:
        labels.update(label_findings([f for f in findings if f["target"] == n], gts.get(n)))

    out = [
        "# noulgrep phase 2 report\n",
        f"Model `{MODEL}`, questions `{QUESTIONS_VERSION}`. {len(T)} findings triaged "
        f"({len(R)} also with the path redacted). Ground truth available for: "
        f"{', '.join(gts) or 'none'}.\n",
    ]
    section_policy(out, names, F, T)
    section_ranked(out, F, T, labels)
    section_suppressed(out, F, T)
    for n in names:
        if n in gts:
            section_eval(out, n, F, T, R, labels, gts[n], [f for f in findings if f["target"] == n])
    return "\n".join(out) + "\n"


def run(args) -> None:
    text = build()
    RESULTS_DIR.mkdir(exist_ok=True)
    REPORT_PATH.write_text(text)
    print(text)
    print(f"written to {REPORT_PATH.relative_to(ROOT)}")
