"""Ground truth: build ground_truth/<target>.yaml from a target's own answer key, and load it.

Juice Shop marks its vulnerable lines in the real source with `// vuln-code-snippet vuln-line
<challengeKey> ...` comments (the coding-challenge feature reads them), and maps each challenge
to a category in data/static/challenges.yml. DVWA is labelled by hand (see its YAML header).
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import yaml

from .questions import VULN_CLASSES
from .targets import GROUND_TRUTH_DIR, load_targets

CATEGORIES = tuple(VULN_CLASSES)

# Juice Shop challenge categories -> the ten classes shared with the Jev vuln_class question.
JUICE_CATEGORY = {
    "Injection": "injection",
    "XSS": "xss",
    "XXE": "injection",
    "Broken Authentication": "auth",
    "Broken Access Control": "authz",
    "Cryptographic Issues": "crypto",
    "Insecure Deserialization": "deserialization",
    "Security Misconfiguration": "config",
    "Sensitive Data Exposure": "other",
    "Improper Input Validation": "other",
    "Unvalidated Redirects": "other",
    "Vulnerable Components": "other",
    "Broken Anti Automation": "other",
    "Security through Obscurity": "other",
    "Observability Failures": "other",
    "Miscellaneous": "other",
}

VULN_LINE_RE = re.compile(r"vuln-code-snippet vuln-line((?:\s+[A-Za-z0-9]+Challenge)+)\s*$")
BLOCK_RE = re.compile(r"vuln-code-snippet (start|end)((?:\s+[A-Za-z0-9]+Challenge)+)\s*$")
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "codefixes", ".ai"}
SOURCE_SUFFIXES = {".ts", ".js", ".yml", ".yaml", ".sol", ".tf", ".json", ".html"}


def iter_source_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_dir() or path.suffix not in SOURCE_SUFFIXES:
            continue
        rel = path.relative_to(root)
        if SKIP_DIRS & set(rel.parts) or rel.parts[0] == "test":
            continue
        yield path, rel.as_posix()


def collapse_ranges(lines: list[int]) -> list[list[int]]:
    """[16, 18, 20, 21] -> [[16, 16], [18, 18], [20, 21]]."""
    out: list[list[int]] = []
    for n in sorted(set(lines)):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return out


def juice_challenges(root: Path) -> dict[str, dict]:
    data = yaml.safe_load((root / "data/static/challenges.yml").read_text())
    entries = data["challenges"] if isinstance(data, dict) else data
    return {c["key"]: c for c in entries}


def build_juice_shop() -> dict:
    t = next(t for t in load_targets() if t.name == "juice-shop")
    challenges = juice_challenges(t.path)
    lines_by_key: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    blocks: dict[str, dict[str, list[int]]] = defaultdict(dict)
    for path, rel in iter_source_files(t.path):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if "vuln-code-snippet" not in text:
            continue
        for n, line in enumerate(text.split("\n"), 1):
            m = VULN_LINE_RE.search(line)
            if m:
                for key in m.group(1).split():
                    lines_by_key[key][rel].append(n)
                continue
            m = BLOCK_RE.search(line)
            if m:
                for key in m.group(2).split():
                    blocks[key].setdefault(rel, [None, None])
                    blocks[key][rel][0 if m.group(1) == "start" else 1] = n
    vulns = []
    for key in sorted(lines_by_key):
        ch = challenges.get(key, {})
        raw_cat = ch.get("category", "Miscellaneous")
        excluded = t.exclude
        notes = [f"{ch.get('name', key)!r}: {raw_cat}."]
        if ch.get("description"):
            notes.append(re.sub(r"<[^>]+>", "", ch["description"]).strip())
        locations = []
        for rel, nums in sorted(lines_by_key[key].items()):
            for start, end in collapse_ranges(nums):
                loc = {"path": rel, "lines": [start, end]}
                if any(rel == ex or rel.startswith(ex.rstrip("/") + "/") for ex in excluded):
                    loc["scanned"] = False  # frontend/ is excluded from the Semgrep run
                locations.append(loc)
            b = blocks.get(key, {}).get(rel)
            if b and all(b):
                notes.append(f"snippet block in {rel}: lines {b[0]}-{b[1]}.")
        vulns.append(
            {
                "id": key,
                "category": JUICE_CATEGORY.get(raw_cat, "other"),
                "source": f"vuln-code-snippet vuln-line marker; challenges.yml key {key}",
                "locations": locations,
                "notes": " ".join(notes),
            }
        )
    return {"target": t.name, "sha": t.sha, "vulns": vulns}


BUILDERS = {"juice-shop": build_juice_shop}

HEADER = {
    "juice-shop": (
        "# Ground truth for juice-shop. Schema: ground_truth/README.md.\n"
        "# Generated by `noulgrep ground-truth juice-shop` from the vuln-code-snippet vuln-line\n"
        "# markers in the source and the category field of data/static/challenges.yml. Category\n"
        "# mapping: noulgrep/ground_truth.py JUICE_CATEGORY. Locations under frontend/ carry\n"
        "# scanned: false because the frontend is excluded from the Semgrep run.\n"
    ),
}


def write(name: str, doc: dict) -> Path:
    path = GROUND_TRUTH_DIR / f"{name}.yaml"
    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100)
    path.write_text(HEADER.get(name, "") + body)
    return path


def load(name: str) -> dict:
    """Load and validate one ground truth file. Raises ValueError on schema problems."""
    doc = yaml.safe_load((GROUND_TRUTH_DIR / f"{name}.yaml").read_text())
    problems = []
    if doc.get("target") != name:
        problems.append(f"target field is {doc.get('target')!r}, expected {name!r}")
    ids = [v.get("id") for v in doc.get("vulns", [])]
    if len(ids) != len(set(ids)):
        problems.append("duplicate vuln ids")
    for v in doc.get("vulns", []):
        if v.get("category") not in CATEGORIES:
            problems.append(f"{v.get('id')}: category {v.get('category')!r}")
        for loc in v.get("locations", []):
            lines = loc.get("lines")
            if not (isinstance(lines, list) and len(lines) == 2 and lines[0] <= lines[1]):
                problems.append(f"{v.get('id')}: bad lines {lines!r} in {loc.get('path')}")
    if problems:
        raise ValueError(f"{name}.yaml: " + "; ".join(problems))
    return doc


def run(args) -> None:
    doc = BUILDERS[args.name]()
    path = write(args.name, doc)
    load(args.name)
    n_loc = sum(len(v["locations"]) for v in doc["vulns"])
    print(
        f"{path.relative_to(GROUND_TRUTH_DIR.parent)}: {len(doc['vulns'])} vulns, {n_loc} locations"
    )
