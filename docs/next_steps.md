# Next steps

State as of 2026-09-20, commit f9daa0d: phases 1 and 2 complete. Semgrep runner, Jev classifier,
ground truth for DVWA and Juice Shop, evaluation report. Headline: on DVWA with the path hidden,
Jev ranks known-vulnerable findings above known-safe controls with AUC 0.87; Semgrep alone cannot
separate them. Semgrep surfaces roughly one in five of the labelled vulnerabilities. Details in
`phase2-results.md`.

In priority order.

## 1. Ground truth for WebGoat, then NodeGoat

The 0.87 is one target, one language (PHP), 56 positives against 13 controls. WebGoat is Java,
the largest target (251 findings), and its `introduction/` vs `mitigation/` sub-packages give
known-safe controls the way DVWA's `impossible.php` does. NodeGoat marks every fix with a
`// Fix for A<n>` comment next to the live vulnerable line. Same labelling approach as DVWA
(agent reads each file, records sink lines, validates against the tree), then `noulgrep report`
picks the files up automatically. Outcome: thresholds confirmed or re-derived on two more
languages.

## 2. Questions v2: remove Semgrep's opinion from the state

`rule_message` and `severity` are in the state and the verdict instruction leads with "Semgrep
rule reported". That primes `true_positive`. Bump `QUESTIONS_VERSION`, drop both fields, re-run
the 245 path-redacted findings, compare AUC. Tells us how much of the separation is Jev reading
code versus Jev reading Semgrep. Cost: about two cents.

## 3. Context-size experiment

`normalise --context 40`, re-classify DVWA path-redacted, see whether `exec/impossible` moves off
P(tp) 0.72 and whether the two `needs_context` escape hatches ever fire. Also worth trying the
other direction (5 lines) to find where the signal comes from.

## 4. Generative baseline

Same 245 findings through one frontier model with a JSON-output prompt asking the same five
questions. Record cost, latency, agreement with Jev and with ground truth, and the rate of
malformed or off-schema answers. This is the comparison the write-up needs. Needs a second API
key.

## 5. Policy refinements, when there is more ground truth

- Route `is_test_file` and `is_fixture` findings out of the ranked list by default; the model's
  `in_dead_or_test_code` Noul is not usable (310 false alarms) and stays as a feature only.
- Down-weight `exploitability` when `sanitised` is high; currently they are independent signals.
- Per-rule thresholds for the three noise rules (`github-actions-mutable-action-tag`,
  `django-no-csrf-token`, `detected-jwt-token`) once WebGoat/NodeGoat labels exist.

## Open items carried from the handoff

- Max state size: still untested. Do it before any context experiment above 40 lines.
- Rate limits: not verified numerically. 15 calls/s at concurrency 8 to 16 produced no 429s.
- `jev-preview` exists alongside `jev-latest`; not evaluated.

## Not doing

- Populating ground truth for crAPI or VAmPI yet. crAPI's flaws are mostly API logic Semgrep
  does not see; VAmPI produced 8 findings. Neither adds much to the classifier question.
- Touching the Semgrep side. Coverage is Semgrep's ceiling and out of scope for this project.
