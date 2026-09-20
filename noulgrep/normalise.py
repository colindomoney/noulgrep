"""Raw Semgrep JSON -> results/findings.jsonl, one object per finding in the phase 2 state schema.

Findings are deduplicated across rulesets on (target, path, start_line, end_line, rule_id); the
`rulesets` list records every pack that produced the same match. Every row carries every key in
SCHEMA, nulls allowed, so phase 2 loads it with no schema guessing.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from .scan import RESULTS_DIR, load_manifest, log
from .targets import ROOT, Target, load_targets

FINDINGS_PATH = RESULTS_DIR / "findings.jsonl"

SCHEMA = (
    "finding_id",
    "target",
    "rulesets",
    "rule_id",
    "rule_message",
    "severity",
    "cwe",
    "owasp",
    "confidence",
    "language",
    "path",
    "start_line",
    "end_line",
    "snippet",
    "context",
    "is_test_file",
    "is_vendored",
    "is_fixture",
    "target_meta",
)

EXT_LANGUAGE = {
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".groovy": "groovy",
    ".gradle": "groovy",
    ".py": "python",
    ".go": "go",
    ".php": "php",
    ".phtml": "php",
    ".php3": "php",
    ".php4": "php",
    ".php5": "php",
    ".inc": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".scala": "scala",
    ".swift": "swift",
    ".sh": "bash",
    ".bash": "bash",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".vue": "vue",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".tf": "terraform",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "config",
    ".properties": "properties",
    ".env": "env",
    ".md": "markdown",
    ".txt": "text",
    ".adoc": "asciidoc",
    ".hbs": "handlebars",
    ".ejs": "ejs",
    ".key": "pem",
    ".pem": "pem",
    ".crt": "pem",
    ".npmrc": "config",
    ".htaccess": "config",
    ".template": "config",
}
FILENAME_LANGUAGE = {"Dockerfile": "dockerfile", "Makefile": "make", ".env": "env"}

TEST_DIRS = {"test", "tests", "spec", "__tests__", "testsuite"}
VENDOR_DIRS = {"node_modules", "vendor", "third_party", "thirdparty"}
# Third-party code that lives outside the generic vendor directory names (confirmed per tree).
TARGET_VENDOR_PREFIXES = {
    "nodegoat": ("app/assets/vendor/",),  # jquery, bootstrap, morris, raphael
    "dvwa": ("external/", "dvwa/includes/Parsedown.php"),
}
FIXTURE_DIRS = {
    "fixtures",
    "fixture",
    "examples",
    "example",
    "docs",
    "doc",
    "samples",
    "sample",
    "demo",
    "testdata",
    "codefixes",
}
TEST_FILE_RE = re.compile(r"\.(test|spec)\.[^./]+$")  # foo.test.js, foo.spec.ts
# test_x.py, x_test.py, x_test.go, tests.py (Django), FooTest.java / FooTests.java
TEST_NAME_RE = re.compile(r"^(test_[^/]*\.py|[^/]*_test\.(py|go)|tests?\.py|[^/]*Tests?\.java)$")


def language_for(path: str, rule_id: str) -> str:
    name = Path(path).name
    if name in FILENAME_LANGUAGE:
        return FILENAME_LANGUAGE[name]
    if name.startswith("Dockerfile"):
        return "dockerfile"
    suffixes = [sfx.lower() for sfx in Path(path).suffixes]
    if suffixes and suffixes[-1] == ".template" and len(suffixes) > 1:
        suffixes.pop()  # nginx.conf.template -> .conf
    if suffixes and suffixes[-1] in EXT_LANGUAGE:
        return EXT_LANGUAGE[suffixes[-1]]
    if name.lower() in EXT_LANGUAGE:  # dotfiles such as .npmrc, .htaccess
        return EXT_LANGUAGE[name.lower()]
    head = rule_id.split(".", 1)[0]
    return head if head and head != "generic" else "unknown"


def path_flags(path: str, target: str = "") -> tuple[bool, bool, bool]:
    """(is_test_file, is_vendored, is_fixture), all deterministic from the relative path."""
    parts = path.split("/")
    dirs = {p.lower() for p in parts[:-1]}
    name = parts[-1]
    is_test = (
        bool(dirs & TEST_DIRS) or bool(TEST_FILE_RE.search(name)) or bool(TEST_NAME_RE.match(name))
    )
    vendored = bool(dirs & VENDOR_DIRS) or any(
        path.startswith(prefix) for prefix in TARGET_VENDOR_PREFIXES.get(target, ())
    )
    return is_test, vendored, bool(dirs & FIXTURE_DIRS)


# --- target-specific deterministic labels -------------------------------------------------------
# Path patterns confirmed against the pinned checkouts; see the notes field in targets.toml.

# Level files are <level>.php; extra files in source/ carry the level as a name token
# (check_token_high.php, jsonp_impossible.php, high_unobfuscated.js).
DVWA_SOURCE_RE = re.compile(r"^vulnerabilities/([^/]+)/source/([^/]+)$")
DVWA_LEVEL_RE = re.compile(r"(?:^|_)(low|medium|high|impossible)(?=_|\.)")
DVWA_MODULE_RE = re.compile(r"^vulnerabilities/([^/]+)/")
CRAPI_SERVICE_RE = re.compile(r"^services/([^/]+)/")
WEBGOAT_LESSON_RE = re.compile(r"^src/(?:main|test)/(java|resources)/(?:.*/)?lessons/([^/]+)/(.*)$")
# mitigation/ sub-package or an explicit *Mitigation* / *SecureController* / *Fixed* class name.
# "Secure" alone is not used: the securepasswords lesson's own classes start with it.
WEBGOAT_MITIGATION_RE = re.compile(r"(/mitigation/|Mitigation|SecureController|Fixed)")
# data/static/codefixes/<challengeKey>_<n>[_correct].<ext>; the _correct variant is the fix.
JUICE_CODEFIX_RE = re.compile(r"^data/static/codefixes/([A-Za-z0-9]+)_(\d+)(_correct)?\.\w+$")
VAMPI_VIEW_RE = re.compile(r"^api_views/([^/]+)\.py$")


def top_dir(path: str) -> str:
    return path.split("/", 1)[0] if "/" in path else "(root)"


def meta_dvwa(path: str) -> dict:
    m = DVWA_SOURCE_RE.match(path)
    if m:
        module, filename = m.groups()
        meta: dict = {"module": module}
        level = DVWA_LEVEL_RE.search(filename)
        if level:
            meta["security_level"] = level.group(1)
        return meta
    m = DVWA_MODULE_RE.match(path)
    return {"module": m.group(1)} if m else {}


def meta_crapi(path: str) -> dict:
    m = CRAPI_SERVICE_RE.match(path)
    return {"service": m.group(1)} if m else {"area": top_dir(path)}


def meta_webgoat(path: str) -> dict:
    m = WEBGOAT_LESSON_RE.match(path)
    if not m:
        return {}
    kind, lesson, rest = m.groups()
    meta: dict = {"lesson": lesson, "kind": "resource" if kind == "resources" else "java"}
    if "/" in rest:
        meta["sub"] = rest.split("/", 1)[0]
    meta["mitigation"] = bool(WEBGOAT_MITIGATION_RE.search("/" + rest))
    return meta


def meta_juice_shop(path: str) -> dict:
    meta: dict = {"area": top_dir(path)}
    m = JUICE_CODEFIX_RE.match(path)
    if m:
        key, variant, correct = m.groups()
        meta["codefix"] = {
            "challenge": key,
            "variant": int(variant),
            "correct": correct is not None,
        }
    return meta


def meta_nodegoat(path: str) -> dict:
    parts = path.split("/")
    if parts[0] == "app" and len(parts) > 2:
        return {"area": f"app/{parts[1]}"}
    return {"area": top_dir(path)}


def meta_vampi(path: str) -> dict:
    m = VAMPI_VIEW_RE.match(path)
    return {"module": m.group(1)} if m else {}


TARGET_META: dict[str, Callable[[str], dict]] = {
    "dvwa": meta_dvwa,
    "crapi": meta_crapi,
    "webgoat": meta_webgoat,
    "juice-shop": meta_juice_shop,
    "nodegoat": meta_nodegoat,
    "vampi": meta_vampi,
}

# --- building rows ------------------------------------------------------------------------------

_FILE_CACHE: dict[Path, list[str] | None] = {}


def file_lines(path: Path) -> list[str] | None:
    """Lines of a file split on \\n only, so indices line up with Semgrep's line numbers."""
    if path not in _FILE_CACHE:
        try:
            _FILE_CACHE[path] = path.read_text(errors="replace").split("\n")
        except OSError:
            _FILE_CACHE[path] = None
    return _FILE_CACHE[path]


def as_list(value) -> list[str]:
    """Semgrep metadata gives cwe/owasp as either a string or a list; normalise to a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple):
        return [str(v) for v in value]
    return [str(value)]


def finding_id(target: str, path: str, start: int, end: int, rule_id: str) -> str:
    key = "\0".join([target, path, str(start), str(end), rule_id])
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def build_finding(t: Target, ruleset: str, r: dict, n_ctx: int) -> dict:
    extra = r.get("extra") or {}
    meta = extra.get("metadata") or {}
    path = r["path"].removeprefix("./")
    start, end = int(r["start"]["line"]), int(r["end"]["line"])
    lines = file_lines(t.path / path)
    if lines is None:
        snippet = extra.get("lines") or ""
        context = snippet
    else:
        snippet = "\n".join(lines[start - 1 : end])
        lo, hi = max(0, start - 1 - n_ctx), min(len(lines), end + n_ctx)
        context = "\n".join(lines[lo:hi])
    is_test, is_vendored, is_fixture = path_flags(path, t.name)
    return {
        "finding_id": finding_id(t.name, path, start, end, r["check_id"]),
        "target": t.name,
        "rulesets": [ruleset],
        "rule_id": r["check_id"],
        "rule_message": extra.get("message") or "",
        "severity": extra.get("severity"),
        "cwe": as_list(meta.get("cwe")),
        "owasp": as_list(meta.get("owasp")),
        "confidence": meta.get("confidence"),
        "language": language_for(path, r["check_id"]),
        "path": path,
        "start_line": start,
        "end_line": end,
        "snippet": snippet,
        "context": context,
        "is_test_file": is_test,
        "is_vendored": is_vendored,
        "is_fixture": is_fixture,
        "target_meta": TARGET_META.get(t.name, lambda _p: {})(path),
    }


def run(args) -> None:
    n_ctx = getattr(args, "context", 15)
    manifest = load_manifest()
    targets = {t.name: t for t in load_targets()}
    selected = set(args.target) if args.target else set(targets)
    findings: dict[tuple, dict] = {}
    runs_used = 0
    for rec in manifest.get("runs", {}).values():
        if rec.get("status") not in ("ok", "partial") or rec["target"] not in selected:
            continue
        raw = ROOT / rec["raw_path"]
        if not raw.exists():
            log(f"[{rec['target']}] {rec['ruleset']}: raw file missing, skipping")
            continue
        t = targets[rec["target"]]
        data = json.loads(raw.read_text())
        runs_used += 1
        for r in data.get("results") or []:
            path = r["path"].removeprefix("./")
            key = (t.name, path, int(r["start"]["line"]), int(r["end"]["line"]), r["check_id"])
            if key in findings:
                if rec["ruleset"] not in findings[key]["rulesets"]:
                    findings[key]["rulesets"].append(rec["ruleset"])
                continue
            findings[key] = build_finding(t, rec["ruleset"], r, n_ctx)

    rows = sorted(
        findings.values(), key=lambda f: (f["target"], f["path"], f["start_line"], f["rule_id"])
    )
    RESULTS_DIR.mkdir(exist_ok=True)
    with FINDINGS_PATH.open("w") as fh:
        for f in rows:
            f["rulesets"].sort()
            assert set(f) == set(SCHEMA), f"schema drift: {sorted(set(f) ^ set(SCHEMA))}"
            fh.write(json.dumps({k: f[k] for k in SCHEMA}, ensure_ascii=False) + "\n")

    per_target = Counter(f["target"] for f in rows)
    rel = FINDINGS_PATH.relative_to(ROOT)
    log(f"normalised {len(rows)} unique findings from {runs_used} runs -> {rel}")
    for name in targets:
        if name in selected:
            log(f"  {name:10} {per_target.get(name, 0)}")
