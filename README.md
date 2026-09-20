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

## Running phase 2 (Jev)

```bash
uv run noulgrep ground-truth juice-shop   # ground_truth/juice-shop.yaml from the vuln-line markers
uv run noulgrep classify                  # Jev over findings.jsonl -> results/triaged-full.jsonl
uv run noulgrep classify --redact-path --target dvwa --target juice-shop   # -> triaged-redacted.jsonl
uv run noulgrep report                    # policy buckets, ranking, evaluation -> results/report.md
```

`classify` is resumable (re-running skips finding_ids already in the output; `--force` starts over)
and pins the model and question set in `noulgrep/questions.py`. `--redact-path` hides the file path
from Jev, which matters for DVWA where `source/impossible.php` in the path is the answer. The
whole corpus (731 findings) classifies in about 15 seconds for roughly five cents.
`ground_truth/dvwa.yaml` is labelled by hand (see its header); the others are still headers.

## Hello, Jev

`hello_jev.py` is a standalone tour of the model phase 2 will use: five silly examples (one per
primitive, then several questions in one call, then an eight-question fan-out) followed by timing
analysis (questions vs latency, sequential vs concurrent, server time vs network). It needs
`TYPESAFE_API_KEY` in `.env` (copy `.env.example`) and costs well under a cent per run.

```bash
uv run hello_jev.py              # ~45 calls
uv run hello_jev.py --repeats 3 --skip-async
```

It also writes `docs/jev-response-shape.json`, the raw payload that pins down the SDK's response
attribute names; `docs/jev-verified.md` records what that run confirmed about the handoff doc.

Notes:

- `targets/` and `results/` are gitignored. Reproducibility comes from `targets.toml` (URLs and SHAs) and `results/manifest.json` (Semgrep version, ruleset list, per-run status, timing and errors).
- Test directories are scanned on purpose. Semgrep's built-in ignore list silently drops `test/`, `tests/`, `testsuite/` and `*_test.go`; noulgrep writes its own `.semgrepignore` into each target checkout to override that, and tags such findings with `is_test_file` instead.
- In `findings.jsonl`, `snippet` is the matched lines exactly as in the file and `context` is the window of N lines either side *including* the matched lines. Both are read from the pinned checkout, not from Semgrep's (sometimes truncated) `extra.lines`.
- The target applications are never built or run; only their source is read.
