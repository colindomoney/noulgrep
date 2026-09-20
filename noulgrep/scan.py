"""Run Semgrep per target per ruleset, writing raw JSON and results/manifest.json.

Each (target, ruleset) pair is a separate run so findings stay attributable to the pack that
produced them. Community engine only, metrics off, one retry on error, timeouts recorded.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .targets import ROOT, Target, head_sha, load_targets

RESULTS_DIR = ROOT / "results"
RAW_DIR = RESULTS_DIR / "raw"
MANIFEST_PATH = RESULTS_DIR / "manifest.json"

COMMON_RULESETS = ["p/default", "p/owasp-top-ten", "p/security-audit", "p/secrets"]

# Large or generated paths only. Test directories are deliberately NOT excluded: phase 2 wants
# those findings, tagged via is_test_file, so it can learn to discount them.
EXCLUDES = [
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".git",
    "*.min.js",
    "*.min.css",
    "*.map",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
]

SEMGREP_FLAGS = [
    "--json",
    "--time",
    "--metrics=off",
    "--oss-only",
    "--disable-version-check",
    "--timeout=30",
    "--timeout-threshold=5",
    "--max-memory=4000",
]

RUN_TIMEOUT_S = 45 * 60
MAX_ATTEMPTS = 2

# Semgrep's built-in .semgrepignore skips test/, tests/, testsuite/ and *_test.go. A file at the
# project root replaces that list wholesale, so this one keeps only .git and leaves the rest to
# --exclude, where it is visible in the manifest.
SEMGREPIGNORE_MARK = "# written by noulgrep"
SEMGREPIGNORE = (
    f"{SEMGREPIGNORE_MARK}: overrides Semgrep's default ignore list so test dirs are scanned\n"
    ".git/\n"
)


def log(msg: str) -> None:
    print(msg, flush=True)


def tail(text: str | None, n: int = 2000) -> str | None:
    return text[-n:] if text else None


def last_line(text: str | None) -> str:
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def semgrep_bin() -> str:
    """Prefer the semgrep installed in this project's environment over whatever is on PATH."""
    candidate = Path(sys.executable).parent / "semgrep"
    if candidate.exists():
        return str(candidate)
    found = shutil.which("semgrep")
    if not found:
        raise SystemExit("semgrep not found; run `uv sync`")
    return found


def semgrep_env(bin_path: str) -> dict[str, str]:
    """PATH with the venv first: the semgrep wrapper locates semgrep-core via PATH, and a
    Homebrew semgrep-core of a different version would silently win otherwise."""
    venv_bin = str(Path(bin_path).parent)
    return {**os.environ, "PATH": venv_bin + os.pathsep + os.environ.get("PATH", "")}


def semgrep_version(bin_path: str) -> str:
    proc = subprocess.run(
        [bin_path, "--version"],
        capture_output=True,
        text=True,
        check=True,
        env=semgrep_env(bin_path),
    )
    return proc.stdout.strip().splitlines()[-1]


def install_semgrepignore(repo: Path) -> str | None:
    """Write our .semgrepignore into the checkout. Returns the target's own file if it had one."""
    path = repo / ".semgrepignore"
    original = None
    if path.exists():
        current = path.read_text()
        if current.startswith(SEMGREPIGNORE_MARK):
            return None
        original = current
    path.write_text(SEMGREPIGNORE)
    return original


def raw_path(target: str, ruleset: str) -> Path:
    return RAW_DIR / target / (ruleset.replace("/", "_") + ".json")


def slim_time_block(data: dict) -> dict | None:
    """Drop Semgrep's per-(rule, file) timing arrays in place; return an aggregate summary.

    With --time, every scanned file carries one float per rule for matching and parsing, which
    is tens of MB per run on the bigger targets. Per-file run_time and the totals are kept.
    """
    t = data.get("time")
    if not t:
        return None
    files = t.get("targets") or []
    for entry in files:
        entry.pop("match_times", None)
        entry.pop("parse_times", None)
    slowest = sorted(files, key=lambda e: e.get("run_time") or 0.0, reverse=True)[:10]
    keys = (
        "rules_parse_time",
        "parsing_time",
        "matching_time",
        "tainting_time",
        "scanning_time",
        "total_bytes",
        "max_memory_bytes",
        "profiling_times",
    )
    summary = {k: t.get(k) for k in keys}
    summary["rules"] = len(t.get("rules") or [])
    summary["files_timed"] = len(files)
    summary["slowest_files"] = [
        {"path": e.get("path"), "run_time": e.get("run_time"), "num_bytes": e.get("num_bytes")}
        for e in slowest
    ]
    return summary


def build_command(bin_path: str, t: Target, ruleset: str) -> list[str]:
    cmd = [bin_path, "scan", f"--config={ruleset}", *SEMGREP_FLAGS]
    cmd += [f"--exclude={pattern}" for pattern in [*EXCLUDES, *t.exclude]]
    cmd.append(".")
    return cmd


def new_record(t: Target, ruleset: str, cmd: list[str]) -> dict:
    return {
        "target": t.name,
        "ruleset": ruleset,
        "status": None,
        "exit_code": None,
        "attempts": 0,
        "wall_seconds": None,
        "findings": None,
        "semgrep_errors": None,
        "error_types": {},
        "error_messages": [],
        "paths_scanned": None,
        "paths_skipped": None,
        "semgrep_version": None,
        "time": None,
        "stderr_tail": None,
        "raw_path": str(raw_path(t.name, ruleset).relative_to(ROOT)),
        "started_at": None,
        "command": "semgrep " + " ".join(cmd[1:]),
    }


def error_type(e: dict) -> str:
    """Semgrep's error `type` is a string for most errors but a list for some (PartialParsing)."""
    t = e.get("type", "?")
    if isinstance(t, list):
        return str(t[0]) if t else "?"
    return str(t)


def ingest(record: dict, proc: subprocess.CompletedProcess, out: Path) -> bool:
    """Fill the record from one semgrep invocation. Returns True when no retry is warranted."""
    record["exit_code"] = proc.returncode
    record["stderr_tail"] = tail(proc.stderr)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict) or "results" not in data:
        record["status"] = "error"
        return False
    errors = data.get("errors") or []
    results = data.get("results") or []
    messages = [str(e.get("message", "")) for e in errors if e.get("level") == "error"]
    record["error_messages"] = messages[:5]
    record["semgrep_errors"] = len(errors)
    record["error_types"] = dict(Counter(error_type(e) for e in errors).most_common(10))
    record["semgrep_version"] = data.get("version")
    if proc.returncode not in (0, 1) and not results:
        # Semgrep still prints JSON when the config itself failed (e.g. exit 7 with
        # "Failed to download configuration ... HTTP 404"). No data, so this is an error.
        record["status"] = "error"
        return False
    paths = data.get("paths") or {}
    record.update(
        # 0 = no findings, 1 = findings; other exit codes with results are kept as partial
        status="ok" if proc.returncode in (0, 1) else "partial",
        findings=len(results),
        paths_scanned=len(paths.get("scanned") or []),
        paths_skipped=len(paths.get("skipped") or []),
        time=slim_time_block(data),
    )
    with out.open("w") as f:
        json.dump(data, f)
    return True


def run_one(bin_path: str, t: Target, ruleset: str) -> dict:
    out = raw_path(t.name, ruleset)
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = build_command(bin_path, t, ruleset)
    record = new_record(t, ruleset, cmd)
    env = semgrep_env(bin_path)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        record["attempts"] = attempt
        record["started_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd, cwd=t.path, env=env, capture_output=True, text=True, timeout=RUN_TIMEOUT_S
            )
        except subprocess.TimeoutExpired as e:
            record["status"] = "timeout"
            record["wall_seconds"] = round(time.perf_counter() - t0, 1)
            record["stderr_tail"] = tail(e.stderr if isinstance(e.stderr, str) else None)
            return record  # a 45-minute run is not worth a second attempt
        record["wall_seconds"] = round(time.perf_counter() - t0, 1)
        try:
            if ingest(record, proc, out):
                return record
        except Exception as exc:
            # A bug in our own post-processing must not kill a long batch; keep the payload.
            out.with_suffix(".failed-ingest.json").write_text(proc.stdout)
            record["status"] = "error"
            record["stderr_tail"] = f"noulgrep failed to ingest semgrep output: {exc!r}"
            return record
    return record


def load_manifest() -> dict:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text())
    return {
        "generated_at": None,
        "semgrep": {},
        "rulesets": {"common": COMMON_RULESETS, "language_packs": {}},
        "targets": {},
        "runs": {},
    }


def save_manifest(m: dict) -> None:
    m["generated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    RESULTS_DIR.mkdir(exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(m, indent=2) + "\n")


def rulesets_for(t: Target) -> list[str]:
    return [*COMMON_RULESETS, *t.rulesets]


def wanted_ruleset(name: str, wanted: list[str] | None) -> bool:
    return not wanted or name in wanted or name.removeprefix("p/") in wanted


def describe(rec: dict) -> str:
    if rec["status"] in ("ok", "partial"):
        return (
            f"{rec['status']}  {rec['findings']} findings, {rec['paths_scanned']} files, "
            f"{rec['semgrep_errors']} semgrep errors, {rec['wall_seconds']}s"
        )
    detail = (rec.get("error_messages") or [last_line(rec["stderr_tail"])])[0]
    return (
        f"{rec['status'].upper()} exit={rec['exit_code']} after {rec['attempts']} attempt(s), "
        f"{rec['wall_seconds']}s :: {detail[:200]}"
    )


def run(args) -> None:
    targets = load_targets(args.target)
    wanted = getattr(args, "ruleset", None)
    force = getattr(args, "force", False)
    bin_path = semgrep_bin()
    version = semgrep_version(bin_path)
    manifest = load_manifest()
    manifest["semgrep"] = {
        "version": version,
        "path": bin_path,
        "flags": SEMGREP_FLAGS,
        "excludes": EXCLUDES,
        "run_timeout_seconds": RUN_TIMEOUT_S,
        "max_attempts": MAX_ATTEMPTS,
        "semgrepignore": SEMGREPIGNORE,
    }
    manifest["rulesets"]["common"] = COMMON_RULESETS
    log(f"semgrep {version} ({bin_path})")

    for t in targets:
        if not t.path.exists():
            log(f"[{t.name}] not cloned; run `noulgrep targets` first")
            continue
        sha_now = head_sha(t.path)
        if t.sha and sha_now != t.sha:
            log(f"[{t.name}] WARNING checkout at {sha_now[:12]} but manifest pins {t.sha[:12]}")
        prev = manifest["targets"].get(t.name, {})
        original = install_semgrepignore(t.path)
        if original is None:
            original = prev.get("semgrepignore_original")
        manifest["targets"][t.name] = {
            "url": t.url,
            "sha": t.sha,
            "sha_at_scan": sha_now,
            "branch": t.branch,
            "languages": t.languages,
            "exclude": t.exclude,
            "had_semgrepignore": original is not None,
            "semgrepignore_original": original,
        }
        manifest["rulesets"]["language_packs"][t.name] = t.rulesets

        for ruleset in rulesets_for(t):
            if not wanted_ruleset(ruleset, wanted):
                continue
            key = f"{t.name}/{ruleset}"
            done = manifest["runs"].get(key, {}).get("status") in ("ok", "partial")
            if raw_path(t.name, ruleset).exists() and done and not force:
                log(f"[{t.name}] {ruleset}: skip, raw output exists (--force to re-run)")
                continue
            log(f"[{t.name}] {ruleset}: running")
            rec = run_one(bin_path, t, ruleset)
            manifest["runs"][key] = rec
            save_manifest(manifest)  # after every run, so a crash keeps progress
            log(f"[{t.name}] {ruleset}: {describe(rec)}")
            if rec["semgrep_version"] and rec["semgrep_version"] != version:
                log(f"[{t.name}] WARNING run reported semgrep {rec['semgrep_version']}")
    save_manifest(manifest)
    log(f"manifest: {MANIFEST_PATH.relative_to(ROOT)}")
