"""Jev question definitions for Semgrep triage. Versioned: change QUESTIONS_VERSION when any
instruction or criterion changes, because stored distributions are only comparable within a
version and a pinned model.

State field names below are the findings.jsonl keys (see normalise.SCHEMA); every instruction
names the field it is about in backticks.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from typesafe_sdk import Choice, Noul, NoulCriteria, Score

QUESTIONS_VERSION = "v1"
MODEL = "jev-1.13.0"  # pinned: thresholds and agreement figures are for this version

# The ten classes from docs/jev-handoff.md section 5, also used by ground_truth/*.yaml.
VULN_CLASSES = {
    "injection": "SQL, command, LDAP, template, XML entity or similar injection.",
    "xss": "Cross-site scripting of any kind.",
    "auth": "Authentication or session management weakness.",
    "authz": "Missing or broken authorisation / access control.",
    "crypto": "Weak, misused or missing cryptography.",
    "secrets": "Hard-coded credentials or keys.",
    "path": "Path traversal, file inclusion or unsafe file access.",
    "deserialization": "Unsafe deserialisation.",
    "config": "Insecure defaults or misconfiguration.",
    "other": "None of the above.",
}

QUESTIONS = {
    "verdict": Choice(
        instructions=(
            "Semgrep rule `rule_id` reported `snippet` with the message `rule_message`. "
            "Given `snippet` and the surrounding `context`, is this a real vulnerability?"
        ),
        criteria={
            "true_positive": (
                "The dangerous pattern is present and reachable with attacker-influenced "
                "input; the rule fired correctly."
            ),
            "false_positive": (
                "The pattern is present but cannot be reached with attacker-influenced input, "
                "or the input is validated or sanitised before it, or the rule misfired on "
                "unrelated code."
            ),
            "needs_context": (
                "Cannot be decided from `snippet` and `context` alone; the data flow crosses "
                "into code that is not shown."
            ),
            "other": "None of the above fits.",
        },
    ),
    "exploitability": Score(
        instructions=(
            "Assume the finding in `snippet` is a real vulnerability. How exploitable is it, "
            "judging from `context`?"
        ),
        criteria=[
            "Not exploitable in practice; theoretical only.",
            "Exploitable only by an authenticated or local user with unusual preconditions.",
            "Exploitable by an authenticated user with ordinary access.",
            "Exploitable by an unauthenticated remote user with no preconditions.",
        ],
    ),
    "vuln_class": Choice(
        instructions="Which vulnerability class best describes what `snippet` shows?",
        criteria=VULN_CLASSES,
    ),
    "in_dead_or_test_code": Noul(
        instructions=(
            "Is the code in `snippet` and `context` test, example, documentation or otherwise "
            "non-production code?"
        ),
        criteria=NoulCriteria(
            true=(
                "Test cases, fixtures, examples, tutorials, sample data, commented-out code, "
                "or code that is clearly never executed in production."
            ),
            false="Application code that runs in production.",
        ),
    ),
    "sanitised": Noul(
        instructions=(
            "Is the untrusted input that flows into `snippet` validated, escaped, "
            "parameterised or otherwise neutralised somewhere in `context`?"
        ),
        criteria=NoulCriteria(
            true=(
                "A prepared statement, allowlist, type cast, escaping function or equivalent "
                "is applied to the input before it reaches the dangerous call."
            ),
            false="The input reaches the dangerous call unchanged, or no check is visible.",
        ),
    ),
}

# Fields from findings.jsonl that go into the Jev state. Deliberately excluded: target,
# target_meta and rulesets (labels and provenance, not evidence) and finding_id.
STATE_FIELDS = (
    "rule_id",
    "rule_message",
    "severity",
    "cwe",
    "owasp",
    "language",
    "path",
    "start_line",
    "end_line",
    "snippet",
    "context",
    "is_test_file",
    "is_vendored",
    "is_fixture",
)


def build_state(finding: dict, redact_path: bool = False) -> dict:
    """Project a finding onto the state object.

    redact_path replaces the path with a neutral one that keeps only the extension. Needed for
    an honest DVWA evaluation, where `source/impossible.php` in the path is the answer.
    """
    state = {k: finding[k] for k in STATE_FIELDS}
    state["semgrep_confidence"] = finding["confidence"]
    if redact_path:
        suffix = PurePosixPath(finding["path"]).suffix
        state["path"] = f"redacted/{finding['finding_id'][:8]}{suffix}"
    return state
