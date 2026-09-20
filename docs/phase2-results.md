# Phase 2 results: Jev over Semgrep findings (2026-09-20)

Model `jev-1.13.0` (what `jev-latest` resolved to), questions `v1` (`noulgrep/questions.py`),
Semgrep 1.177.0, targets at the SHAs in `targets.toml`. Full tables in `results/report.md`
(regenerate with `uv run noulgrep report`).

## Run

- 731 unique findings, five questions each, one call per finding: **15.3 s at concurrency 16,
  1.23 M input tokens, $0.05**. Median call 309 ms, p95 471 ms, no rate-limit errors.
- A second pass with the file path redacted (DVWA + juice-shop, 245 findings, 5.7 s, $0.02),
  because for DVWA `source/impossible.php` in the path is the answer.

## Ground truth

- **DVWA**: 57 vulnerable entries (19 modules × low/medium/high) and 19 controls
  (`impossible.php`), labelled by hand to the sink line (`ground_truth/dvwa.yaml`).
- **Juice Shop**: 35 challenges from the `vuln-code-snippet vuln-line` markers in the source,
  41 locations, generated (`noulgrep ground-truth juice-shop`). No controls.

## What Semgrep alone does

- Covers **22 of 113** DVWA ground-truth locations and **9 of 33** scanned Juice Shop ones.
  Everything it misses is logic: authorisation checks, brute-force limits, CAPTCHA re-verification,
  weak session IDs, the chatbot prompt injection. Jev cannot rank what Semgrep never reports;
  this is the ceiling on recall for the whole pipeline.
- Cannot separate DVWA levels at all: the `exec` module yields the same 10 findings for `low`,
  `medium`, `high` and `impossible`.

## What Jev adds

| | full state | path redacted |
|---|---|---|
| DVWA verdict AUC (known-tp vs controls) | 0.93 | **0.87** |
| P(tp) ≥ 0.8: precision / recall | 1.00 / 0.88 | **0.98 / 0.84** |
| mean P(tp): known-tp / known-fp | 0.90 / 0.44 | 0.88 / 0.65 |
| `vuln_class` agreement on known-tp | 0.79 | – |
| Juice Shop known-tp with P(tp) ≥ 0.8 | 8 / 9 | 8 / 9 |

The path is worth about 0.2 of P(tp) on the controls (0.44 vs 0.65). The redacted numbers are the
honest ones and are what the thresholds were set from.

DVWA `exec`, identical Semgrep output per level, path hidden:

| level | P(tp) | P(sanitised) | exploitability |
|---|---|---|---|
| low | 1.00 | 0.03 | 2.96 |
| medium | 0.98 | 0.27 | 2.91 |
| high | 0.93 | 0.32 | 2.80 |
| impossible | 0.72 | 0.49 | 1.94 |

Monotone in the right direction from the code alone, but `impossible` does not reach "safe".

## Thresholds (pinned in `noulgrep/report.py`)

- **report** at P(true_positive) ≥ 0.80, ranked by P(tp) × (1 + exploitability)
- **suppress** at P(false_positive) ≥ 0.80, logged
- **review** everything else, including `needs_context`

Across the corpus: 265 report, 339 review, 127 suppress. Re-derive if the model or the question
set changes.

## The noise cases from phase 1

| rule | n | outcome |
|---|---|---|
| `detected-jwt-token` (sample tokens in docs/tests) | 37 | all suppressed, mean P(tp) 0.03 |
| `detected-generic-secret` | 18 | 17 suppressed |
| `django-no-csrf-token` on non-Django HTML (WebGoat, NodeGoat) | 90 | 88 to review, mean P(tp) 0.56: not fooled into reporting, not confident enough to suppress |
| `github-actions-mutable-action-tag` | 101 | 89 reported at mean P(tp) 0.87, class `config`. Correct in the narrow sense (the pattern is really there); the ranking has to carry it, and low `exploitability` does push it down |

## Interesting failures

- **Sanitisation Jev cannot see**: DVWA `exec/impossible.php` (octet-by-octet `is_numeric`
  validation) sits at P(tp) 0.50–0.54; `fi/high.php` (`fnmatch("file*")`, bypassable with
  `file:///`) at 0.30 for a real vuln. Both are the "hard limit of not seeing the data flow" the
  handoff predicted, in opposite directions.
- **Obfuscated JS**: `javascript/high.js` (a one-line obfuscated puzzle) gets P(tp) 0.04–0.09 on
  `eval-detected`. Defensible, since the "vulnerability" is a client-side reversing exercise, but the
  ground truth calls it vulnerable.
- **`in_dead_or_test_code` Noul is not usable at 0.5**: 310 non-test findings marked as test code.
  Likely because lesson/CTF code genuinely looks non-production. Use the deterministic
  `is_test_file` flag; keep the Noul only as a feature.
- **`vuln_class` confusion is mostly labelling nuance**: DVWA `bac` (authz) files contain raw SQL,
  which Jev calls `injection`; both are true. Juice Shop's `Observability Failures` map to `other`
  and Jev says `config`; also both defensible.

## Next

1. Populate ground truth for WebGoat (lesson `mitigation/` vs vulnerable) and NodeGoat
   (`// Fix for A<n>` markers) to test the thresholds on Java and a second JS codebase.
2. Context-size experiment: re-normalise at 40 lines and re-classify DVWA; see whether
   `exec/impossible` moves.
3. Generative baseline on the same 245 path-redacted findings: cost, latency, agreement.
