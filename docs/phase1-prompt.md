You are setting up phase 1 of `noulgrep`: a Semgrep runner over a set of deliberately vulnerable repositories. Phase 1 is Semgrep only. Do not touch Jev, do not install `typesafe-sdk`, do not write any classification code. Read `docs/jev-handoff.md` first so you know what phase 2 will need from your output, then do the following.

## Ground rules

- Python only. Use `uv` if it is on the path; otherwise `python -m venv` and `pip`. Do not use Poetry or conda.
- Target repos are not vendored into this repo. They are cloned into `targets/`, which is gitignored. Reproducibility comes from a manifest that pins each one to a commit SHA.
- Do not run any of the target applications. Do not `npm install`, `mvn`, `docker compose up`, or execute anything inside `targets/`. They are vulnerable by design and we are only reading source.
- Do not run Semgrep with `--pro` or log in to Semgrep AppSec Platform. Community engine, registry rulesets, `--metrics=off`.
- Stop at the end of this prompt and report. Do not start on ground truth labelling or Jev integration even if it looks obvious.

## Repo layout to create

```
noulgrep/
  pyproject.toml            # project metadata, pinned semgrep version, ruff
  README.md                 # one paragraph on what noulgrep is, how to run phase 1
  .gitignore                # targets/, results/, .venv/, __pycache__/
  docs/jev-handoff.md       # already present, do not modify
  targets.toml              # manifest: name, url, sha, primary languages, notes
  noulgrep/
    __init__.py
    targets.py              # clone/update targets from the manifest at pinned SHA
    scan.py                 # run semgrep per target per ruleset, write raw JSON
    normalise.py            # raw semgrep JSON -> findings.jsonl in the phase 2 state schema
    summarise.py            # counts per target / severity / rule, top rules, timing
    cli.py                  # `noulgrep targets|scan|normalise|summarise|all`
  results/                  # gitignored; raw/<target>/<ruleset>.json, findings.jsonl, manifest.json, summary.md
  ground_truth/             # empty for now except a README describing the schema (see below)
```

## Step 1: targets manifest and cloner

Create `targets.toml` with these six entries. Clone each with `--depth 1` at the default branch first, record the HEAD SHA into the manifest, then make the cloner idempotent: on subsequent runs it fetches and checks out the pinned SHA rather than moving to a newer HEAD.

| name | url | languages |
|---|---|---|
| juice-shop | https://github.com/juice-shop/juice-shop | typescript, javascript |
| webgoat | https://github.com/WebGoat/WebGoat | java |
| crapi | https://github.com/OWASP/crAPI | java, python, go, javascript |
| nodegoat | https://github.com/OWASP/NodeGoat | javascript |
| vampi | https://github.com/erev0s/VAmPI | python |
| dvwa | https://github.com/digininja/DVWA | php |

For each target, after cloning, spend a few minutes reading its layout and record in the manifest `notes` field anything that will matter for scanning or for later ground truth. Things to look for and confirm (verify against the actual tree, do not assume):

- juice-shop: the challenge catalogue is likely in a YAML under `data/static/`. That is the future answer key. Note its path and the field that maps a challenge to a vulnerability category. Note where the frontend lives and exclude it from scanning unless it contains server-side code.
- webgoat: lessons are likely grouped one directory per lesson under a `lessons` package. Note the path pattern. Some lessons contain both vulnerable and fixed implementations side by side; note if you can tell them apart by filename.
- crapi: polyglot microservices, likely under `services/`. Record the language per service. This is the one that needs per-service language packs.
- nodegoat: check whether fixed versions of vulnerable code exist in the tree alongside the vulnerable ones (the tutorial documents fixes). If so, note how to distinguish them.
- vampi: has a runtime vulnerable/secure toggle. Confirm whether both code paths exist in the same source files (so Semgrep will hit both) or whether the toggle switches modules. Record which.
- dvwa: each vulnerability module should have separate source files per security level (low, medium, high, impossible). Confirm the path pattern. The level in the path is a free deterministic label for phase 2: `impossible` is a known-mitigated control, `low` is known-vulnerable.

## Step 2: Semgrep

Install Semgrep into the project environment and pin the exact version in `pyproject.toml`. Record `semgrep --version` output into `results/manifest.json` along with the target SHAs and the ruleset list.

Rulesets. Run each of these separately per target so results are attributable to the ruleset:

- `p/default`
- `p/owasp-top-ten`
- `p/security-audit`
- `p/secrets`
- language packs chosen per target from the manifest: `p/javascript`, `p/typescript`, `p/nodejs`, `p/express`, `p/java`, `p/spring`, `p/python`, `p/flask`, `p/golang`, `p/php`

Flags: `--json`, `--metrics=off`, `--timeout 30`, `--max-memory 4000`, and a sensible `--exclude` list (`node_modules`, `vendor`, `dist`, `build`, `.git`, minified bundles, lockfiles). Do not exclude test directories; we want those findings, tagged, so phase 2 can learn to discount them. Set `--timeout-threshold` so one pathological file does not kill a whole scan.

Write raw output to `results/raw/<target>/<ruleset>.json`. Capture wall-clock time and Semgrep's own `time` block per run. If a ruleset fails to download or a run errors, record it in the manifest and move on; do not retry more than once.

## Step 3: normalise

Produce `results/findings.jsonl`, one object per finding, deduplicated across rulesets on (target, path, start line, end line, rule id). Keep a `rulesets` list on each finding showing which packs produced it. The schema must match what `docs/jev-handoff.md` section 5 describes as the Jev `state` object, plus provenance:

```
finding_id          stable hash of (target, path, start, end, rule_id)
target
rulesets            list
rule_id
rule_message
severity            semgrep severity as reported
cwe                 list, from metadata, empty list if absent
owasp               list, from metadata, empty list if absent
confidence          semgrep's own metadata.confidence if present, else null
language
path                relative to the target root
start_line
end_line
snippet             the matched lines exactly as in the file
context             N lines either side; make N a parameter, default 15
is_test_file        deterministic from path (test/, tests/, spec/, __tests__/, *.test.*, *.spec.*)
is_vendored         deterministic from path (node_modules/, vendor/, third_party/)
is_fixture          deterministic from path (fixtures/, examples/, docs/, sample data)
target_meta         dict; target-specific deterministic labels, e.g. dvwa security level from path, crapi service name, webgoat lesson name. Empty dict if nothing applies.
```

Every field must be present on every row, nulls allowed, so phase 2 can load this with no schema guessing.

## Step 4: summarise

Write `results/summary.md` with:

- findings per target, total and after dropping `is_vendored`
- findings per target per severity
- top 20 rule ids overall by count, and top 10 per target
- per-ruleset run time and finding count per target
- anything that errored or timed out
- for dvwa specifically: findings per security level, because that is the first sanity check of whether Semgrep alone distinguishes `low` from `impossible` (expect: it mostly does not)

Print the summary to stdout at the end of `noulgrep all`.

## Step 5: ground truth scaffolding only

Create `ground_truth/README.md` describing the schema below and one empty `ground_truth/<target>.yaml` per target containing only the header. Do not populate them.

```yaml
target: juice-shop
sha: <from manifest>
vulns:
  - id: <short slug>
    category: <injection|xss|auth|authz|crypto|secrets|path|deserialization|config|other>
    source: <where the answer key came from, e.g. challenges.yml key or lesson name>
    locations:
      - path: <relative>
        lines: [start, end]
    notes: ""
```

## Report back

When done, give me: the layout you created, the six SHAs, the Semgrep version, the total finding count per target, the three biggest surprises from reading the target trees, and anything in the manifest notes you were not able to confirm. Keep it under a page.
