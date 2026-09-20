"""Async Jev batch over results/findings.jsonl -> results/triaged-<variant>.jsonl.

One system_one call per finding with every question in QUESTIONS; the full probability
distribution, confidence, model, request_id and latency are stored per answer. No thresholds
are applied here: policy lives in report.py.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv
from typesafe_sdk import AsyncTypeSafeClient, TypeSafeAPIError, TypeSafeError

from .normalise import FINDINGS_PATH
from .questions import MODEL, QUESTIONS, QUESTIONS_VERSION, build_state
from .scan import RESULTS_DIR, log
from .targets import ROOT

DEFAULT_CONCURRENCY = 16


def triaged_path(variant: str) -> Path:
    return RESULTS_DIR / f"triaged-{variant}.jsonl"


def load_findings(targets: list[str] | None) -> list[dict]:
    rows = [json.loads(line) for line in FINDINGS_PATH.open() if line.strip()]
    if targets:
        rows = [r for r in rows if r["target"] in targets]
    return rows


def load_done(path: Path) -> set[str]:
    if not path.exists():
        return set()
    done = set()
    for line in path.open():
        if line.strip():
            rec = json.loads(line)
            if not rec.get("error"):
                done.add(rec["finding_id"])
    return done


def answer_to_dict(answer) -> dict:
    """Pydantic answer -> plain dict. Score probabilities/legend are keyed by int level."""
    return answer.model_dump()


async def classify_one(client, sem: asyncio.Semaphore, finding: dict, variant: str) -> dict:
    state = build_state(finding, redact_path=(variant == "redacted"))
    rec = {
        "finding_id": finding["finding_id"],
        "target": finding["target"],
        "variant": variant,
        "questions_version": QUESTIONS_VERSION,
        "model": None,
        "request_id": None,
        "latency_ms": None,
        "usage": None,
        "answers": None,
        "error": None,
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    async with sem:
        t0 = time.perf_counter()
        try:
            r = await client.system_one(state=state, questions=QUESTIONS)
        except TypeSafeAPIError as e:
            rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            rec["error"] = f"{type(e).__name__}: {e}"
            rec["request_id"] = getattr(e, "request_id", None)
            return rec
        except TypeSafeError as e:
            rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            rec["error"] = f"{type(e).__name__}: {e}"
            return rec
    rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    rec["model"] = r.model
    rec["request_id"] = r.request_id
    rec["usage"] = r.usage.model_dump()
    rec["answers"] = {name: answer_to_dict(a) for name, a in r.answers.items()}
    return rec


async def run_batch(findings: list[dict], variant: str, out: Path, concurrency: int) -> Counter:
    sem = asyncio.Semaphore(concurrency)
    stats: Counter = Counter()
    t0 = time.perf_counter()
    with out.open("a") as fh:
        async with AsyncTypeSafeClient(model=MODEL) as client:
            tasks = [classify_one(client, sem, f, variant) for f in findings]
            for i, coro in enumerate(asyncio.as_completed(tasks), 1):
                rec = await coro
                fh.write(json.dumps(rec) + "\n")
                fh.flush()
                stats["error" if rec["error"] else "ok"] += 1
                if rec["usage"]:
                    stats["input_tokens"] += rec["usage"].get("input_tokens") or 0
                if rec["error"] and stats["error"] <= 5:
                    log(f"  error on {rec['finding_id']}: {rec['error'][:160]}")
                if i % 100 == 0 or i == len(findings):
                    log(f"  {i}/{len(findings)}  {time.perf_counter() - t0:.0f}s")
    stats["seconds"] = round(time.perf_counter() - t0, 1)
    return stats


def run(args) -> None:
    load_dotenv(ROOT / ".env")
    if not os.environ.get("TYPESAFE_API_KEY"):
        raise SystemExit("TYPESAFE_API_KEY is not set (see .env.example)")
    variant = "redacted" if args.redact_path else "full"
    out = triaged_path(variant)
    findings = load_findings(args.target)
    if getattr(args, "limit", None):
        findings = findings[: args.limit]
    if args.force and out.exists():
        out.unlink()
    done = load_done(out)
    todo = [f for f in findings if f["finding_id"] not in done]
    log(
        f"classify: {len(todo)} findings to run ({len(done)} already in {out.name}), "
        f"model={MODEL} questions={QUESTIONS_VERSION} variant={variant} "
        f"concurrency={args.concurrency}"
    )
    if not todo:
        return
    RESULTS_DIR.mkdir(exist_ok=True)
    stats = asyncio.run(run_batch(todo, variant, out, args.concurrency))
    cost = stats["input_tokens"] / 1e6 * 0.042
    log(
        f"done: {stats['ok']} ok, {stats['error']} errors, {stats['seconds']}s, "
        f"{stats['input_tokens']} input tokens (~${cost:.4f}) -> {out.relative_to(ROOT)}"
    )
