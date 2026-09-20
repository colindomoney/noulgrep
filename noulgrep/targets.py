"""Clone the target repos listed in targets.toml and pin each to a commit SHA.

First run: shallow-clone the default branch and write HEAD back into the manifest.
Later runs: fetch and check out the pinned SHA; never move to a newer HEAD.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

import tomli_w

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "targets.toml"
TARGETS_DIR = ROOT / "targets"
GROUND_TRUTH_DIR = ROOT / "ground_truth"

GROUND_TRUTH_HEADER = """\
# Ground truth for {name}. Schema: ground_truth/README.md. Header only, not yet populated.
target: {name}
sha: {sha}
vulns: []
"""


@dataclass
class Target:
    name: str
    url: str
    sha: str = ""
    branch: str = ""
    languages: list[str] = field(default_factory=list)
    rulesets: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    notes: str = ""

    @property
    def path(self) -> Path:
        return TARGETS_DIR / self.name


def load_targets(names: list[str] | None = None) -> list[Target]:
    with MANIFEST_PATH.open("rb") as f:
        entries = tomllib.load(f)["targets"]
    targets = [Target(**e) for e in entries]
    if names:
        known = {t.name for t in targets}
        unknown = sorted(set(names) - known)
        if unknown:
            raise SystemExit(f"unknown target(s) {unknown}; known: {sorted(known)}")
        targets = [t for t in targets if t.name in names]
    return targets


def save_targets(targets: list[Target]) -> None:
    """Rewrite targets.toml, keeping the leading comment block by hand (tomli_w drops comments)."""
    header: list[str] = []
    for line in MANIFEST_PATH.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            header.append(line)
        else:
            break
    body = tomli_w.dumps({"targets": [asdict(t) for t in targets]}, multiline_strings=True)
    prefix = "\n".join(header).rstrip("\n")
    MANIFEST_PATH.write_text(f"{prefix}\n\n{body}" if prefix else body)


def git(*args: str, cwd: Path | None = None) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def head_sha(repo: Path) -> str:
    return git("rev-parse", "HEAD", cwd=repo)


def default_branch(repo: Path) -> str:
    try:
        ref = git("symbolic-ref", "--short", "refs/remotes/origin/HEAD", cwd=repo)
    except RuntimeError:
        return ""
    return ref.removeprefix("origin/")


def checkout_pinned(repo: Path, sha: str) -> None:
    git("fetch", "--quiet", "--depth", "1", "origin", sha, cwd=repo)
    git("checkout", "--quiet", "--detach", sha, cwd=repo)


def ensure_target(t: Target) -> str:
    """Clone or update one target in place. Returns a short status word for the log."""
    if not t.path.exists():
        TARGETS_DIR.mkdir(exist_ok=True)
        git("clone", "--quiet", "--depth", "1", t.url, str(t.path))
        status = "cloned"
        if t.sha and head_sha(t.path) != t.sha:
            checkout_pinned(t.path, t.sha)
            status = "cloned+pinned"
    elif not t.sha:
        status = "pinned-existing"
    elif head_sha(t.path) == t.sha:
        status = "already-pinned"
    else:
        checkout_pinned(t.path, t.sha)
        status = "checked-out"
    if not t.sha:
        t.sha = head_sha(t.path)
    if not t.branch:
        t.branch = default_branch(t.path)
    return status


def scaffold_ground_truth(t: Target) -> bool:
    """Write the header-only ground truth file if it does not exist yet. Never overwrites."""
    GROUND_TRUTH_DIR.mkdir(exist_ok=True)
    path = GROUND_TRUTH_DIR / f"{t.name}.yaml"
    if path.exists():
        return False
    path.write_text(GROUND_TRUTH_HEADER.format(name=t.name, sha=t.sha))
    return True


def run(args) -> None:
    everything = load_targets()
    selected = load_targets(args.target) if args.target else everything
    changed = False
    for t in selected:
        before = (t.sha, t.branch)
        try:
            status = ensure_target(t)
        except RuntimeError as e:
            print(f"[{t.name}] ERROR {e}", file=sys.stderr)
            continue
        changed = changed or (t.sha, t.branch) != before
        new_gt = scaffold_ground_truth(t)
        suffix = "  +ground_truth" if new_gt else ""
        print(f"[{t.name:10}] {status:15} {t.sha} ({t.branch or '?'}){suffix}", flush=True)
    if changed:
        updated = {t.name: t for t in selected}
        save_targets([updated.get(t.name, t) for t in everything])
        print(f"pinned SHAs written to {MANIFEST_PATH.name}")
