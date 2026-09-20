# noulgrep

noulgrep runs Semgrep over a set of deliberately vulnerable repositories (Juice Shop, WebGoat, crAPI, NodeGoat, VAmPI, DVWA), each pinned to a commit SHA in `targets.toml`, and normalises every finding into the structured `state` object that phase 2 will hand to Jev (TypeSafe's typed classifier) for triage. Phase 1 is Semgrep only: no classification and no ground-truth labelling, just reproducible raw output, a deduplicated `results/findings.jsonl`, and a summary. `docs/jev-handoff.md` describes what phase 2 does with the output; `docs/phase1-prompt.md` is the phase 1 brief.

## Running phase 1

```bash
uv sync                      # installs the pinned semgrep (community engine) and tomli-w
uv run noulgrep targets      # clone the six targets into targets/ at the pinned SHAs
uv run noulgrep scan         # semgrep per target per ruleset -> results/raw/, results/manifest.json
uv run noulgrep normalise    # -> results/findings.jsonl   (--context N, default 15)
uv run noulgrep summarise    # -> results/summary.md, also printed
uv run noulgrep all          # the four steps in order
```

`--target NAME` restricts any step to one target (repeatable); `scan` also takes `--ruleset NAME` and `--force` (re-run even if raw output exists).

Notes:

- `targets/` and `results/` are gitignored. Reproducibility comes from `targets.toml` (URLs and SHAs) and `results/manifest.json` (Semgrep version, ruleset list, per-run status, timing and errors).
- Test directories are scanned on purpose. Semgrep's built-in ignore list silently drops `test/`, `tests/`, `testsuite/` and `*_test.go`; noulgrep writes its own `.semgrepignore` into each target checkout to override that, and tags such findings with `is_test_file` instead.
- In `findings.jsonl`, `snippet` is the matched lines exactly as in the file and `context` is the window of N lines either side *including* the matched lines. Both are read from the pinned checkout, not from Semgrep's (sometimes truncated) `extra.lines`.
- The target applications are never built or run; only their source is read.
