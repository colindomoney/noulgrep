# Ground truth

One YAML file per target, named after the `name` field in `targets.toml`. Phase 1 creates each
file with a header only; the `vulns` list is populated later, by hand or from each target's own
answer key (Juice Shop's challenge catalogue, WebGoat lesson names, DVWA's per-level source files,
and so on). `noulgrep targets` writes a missing header and never overwrites an existing file.

## Schema

```yaml
target: juice-shop            # must match targets.toml
sha: <commit>                 # the checkout the line numbers refer to; from targets.toml
vulns:
  - id: <short slug>          # unique within the file, e.g. sqli-login
    category: <one of: injection | xss | auth | authz | crypto | secrets | path | deserialization | config | other>
    source: <where the answer key came from, e.g. challenges.yml key or lesson name>
    locations:
      - path: <relative to the target root, same form as findings.jsonl `path`>
        lines: [start, end]   # 1-based, inclusive
    notes: ""
```

Rules:

- `category` uses the same ten values as the phase 2 `vuln_class` question (see
  `docs/jev-handoff.md` section 5), so evaluation is a direct comparison.
- A vuln may have several `locations` (source and sink, or the same flaw repeated per handler).
- If the target ships a fixed variant next to the vulnerable one (DVWA `impossible`, NodeGoat
  commented fixes, VAmPI's secure branch), list only the vulnerable location and say in `notes`
  where the mitigated counterpart lives; that is what lets phase 2 measure false positives on
  known-safe code.
- Line ranges are tied to `sha`. Re-pinning a target invalidates the file.
