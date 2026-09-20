# Jev handoff: context, API, hello world, and two build targets

Written 2026-09-20 for coding agents that have no prior knowledge of Jev. Jev launched on 18 September 2026 and is past most model training cutoffs, so do not rely on training data for anything in this document. Where a field name or limit matters, verify it against https://docs.typesafe.ai before building on it. Anything marked **VERIFY** below was assembled from launch-week sources and has not been confirmed against a live call.

Owner: Colin Domoney. Python only. No JavaScript, no LangChain unless explicitly asked.

---

## 1. What Jev is

Jev is a model from TypeSafe AI (https://typesafe.ai). TypeSafe calls it a "System One model". It is not a chat model and it does not generate text.

You give it:

- **state**: a string, a JSON object, or an array of strings. This is the thing to be judged.
- **questions**: a dictionary of named, typed questions. Each question has a small, fixed answer space that you define.

It returns, for every question, a typed answer plus a probability distribution over the answer space and (for Choice and Score) a confidence value. Every question in a request is evaluated in parallel and in isolation; adding questions barely changes latency.

Three question primitives:

| Primitive | Question shape | Returns |
|---|---|---|
| `Noul` | "Is this statement true?" | a single probability in [0, 1] that the answer is yes |
| `Choice` | "Which one of these options?" (up to 255 options) | winning option, probability per option, confidence |
| `Score` | "Where on this ordered rubric?" (2 to 10 levels, each with a description) | a score (may fall between levels, probability-weighted), probability per level, confidence |

### What it buys you

- The model cannot return an option you did not supply. No off-schema answers, no malformed JSON, no parsing, no retry-on-bad-format loop.
- Probabilities and confidence are first-class outputs, so thresholding and human-review routing are policy code, not prompt engineering.
- Latency is in the 70 to 500 ms range per request (vendor figure). Pricing at launch: $0.042 per million input tokens, output free (vendor figure). Rate limits at launch: roughly 1,200 requests per minute and 250k tokens per second, and TypeSafe says these can change. **VERIFY** current numbers in the console.

### What it does not buy you

- It does not explain itself. There is no rationale, no chain of thought. If a classification is wrong, the fix is in your criteria text, not in a follow-up prompt.
- A valid answer is not a correct answer. It can pick the wrong option from your list with high confidence. Calibration is a population-level property; TypeSafe says so themselves.
- Questions are independent within a request. Answer A does not inform answer B. If B depends on A, that is two requests.
- It is not for generation, extended reasoning, extraction of free text, or anything that needs a paragraph back.

Mental model: Jev is a fast, calibrated classifier with a typed interface. Use it where you would otherwise write "ask the LLM to return JSON with one of these values". Keep control flow in ordinary Python.

---

## 2. API shape

### REST

- `POST https://api.typesafe.ai/v1/systemone`
- Auth: bearer token from `TYPESAFE_API_KEY` (get one at https://console.typesafe.ai)
- Body: `{ "model": "...", "state": <string | object | array>, "questions": { "<name>": {<question spec>}, ... } }`
- Model names: `jev-latest` (alias, default) and versioned strings such as `jev-1.13.0`. Pin a versioned model for anything where thresholds matter, because a model change moves the probabilities.

You will not need raw REST. Use the SDK.

### Python SDK

```bash
pip install typesafe-sdk        # or: uv add typesafe-sdk
export TYPESAFE_API_KEY="..."
```

```python
from typesafe_sdk import (
    TypeSafeClient,
    AsyncTypeSafeClient,
    Choice,
    Score,
    Noul,
    NoulCriteria,
    TypeSafeAPIError,
)
```

Client construction (all optional, env vars are read by default):

```python
client = TypeSafeClient(
    api_key=None,  # falls back to TYPESAFE_API_KEY
    base_url=None,  # falls back to TYPESAFE_BASE_URL, default https://api.typesafe.ai
    model="jev-1.13.0",  # default jev-latest, or TYPESAFE_DEFAULT_MODEL
    timeout=...,  # VERIFY units
    max_retries=...,  # or retry=RetryPolicy(max_retries=, backoff_max=, timeout=)
)
```

Both clients are context managers. The one method that matters:

```python
response = client.system_one(state=..., questions={...})
```

Question constructors:

```python
Noul(
    instructions="Does `message` explicitly communicate time pressure?",
    criteria=NoulCriteria(  # optional but recommended
        true="...what makes this true...",
        false="...what makes this false...",
    ),
)

Choice(
    instructions="What is the customer's main request?",
    criteria={  # key -> description; keys are the returned values
        "refund": "The customer wants money returned.",
        "technical_help": "The customer needs a bug or integration fixed.",
        "other": "None of the options clearly fits.",
    },
)

Score(
    instructions="How frustrated does the customer appear?",
    criteria=[  # ordered list, low to high; index is the level
        "Calm and neutral",
        "Concerned but civil",
        "Very angry",
    ],
)
```

Response object (**VERIFY** exact attribute names on first run; hello world 2 below dumps the raw response for exactly this reason):

```python
response.model  # e.g. "jev-1.13.0"
response.request_id
response.usage  # token counts
response.raw_http_response  # full payload, use this if an attribute is missing

response.nouls["name"].noul  # float, P(true)
response.choices["name"].choice  # str, the winning key
response.choices["name"].probabilities  # dict key -> float
response.choices["name"].confidence  # float
response.scores["name"].score  # float
response.scores["name"].probabilities  # list or dict, per level
response.scores["name"].confidence  # float
response.answers["name"]  # generic access, seen in some samples
```

Errors: `TypeSafeAPIError` with `.status` and `.request_id`.

Async: `AsyncTypeSafeClient` with `await client.system_one(...)`. Use it with `asyncio.gather` and a semaphore for batch work; the rate limit is per minute, not per connection.

### Rules for writing questions

These are the levers. Treat them as code and version them.

1. **Name the field in the instruction.** Put the state in a JSON object and refer to keys in backticks: "Does `finding.snippet` show user-controlled input reaching `finding.sink`?" Vague instructions over a blob of text is how you get vague probabilities.
2. **Every Choice gets an `other` option.** If none of your categories fit, you want to know that rather than have the mass forced onto the least-wrong one.
3. **Score levels are descriptions, not numbers.** "Level 3" means nothing. "Exploitable by an unauthenticated remote user with no preconditions" means something.
4. **Noul instructions are statements to evaluate, not open questions.** Supply `NoulCriteria` for both sides when the boundary is subtle.
5. **Thresholds are per decision, not global.** Act at high confidence, route to review in the middle band, fall back or refuse at the bottom. Set the bands against the cost of a wrong answer for that decision. Do not copy 0.7 from a blog post.
6. **Pin the model version** anywhere a threshold is stored.
7. **Keep a labelled sample and measure agreement** before trusting any threshold. Calibration is population-level; your population is not TypeSafe's.

---

## 3. Hello world

Three scripts. Run them in order. Each one is a gate: do not move on until the previous one prints sensible output.

### Hello world 1: one Noul, prove the key works

`hello_1_noul.py`

```python
"""Smallest possible Jev call. Proves auth, network and the SDK import."""

from typesafe_sdk import TypeSafeClient, Noul

with TypeSafeClient() as client:
    r = client.system_one(
        state={"message": "I was charged twice and need the duplicate refunded today."},
        questions={
            "is_urgent": Noul(instructions="Does `message` explicitly communicate time pressure?"),
        },
    )

print("model:", r.model)
print("P(urgent):", r.nouls["is_urgent"].noul)
```

Expected: a model string and a probability well above 0.5.

### Hello world 2: all three primitives, dump the raw response

`hello_2_mixed.py`

This is the one that resolves every **VERIFY** in section 2. Keep its output; paste the raw JSON into a `docs/jev-response-shape.json` file in whichever repo you are working in.

```python
"""All three primitives in one call. Prints the typed accessors and the raw payload."""

import json
from typesafe_sdk import TypeSafeClient, Choice, Score, Noul, NoulCriteria

STATE = {
    "message": "Your deploy broke checkout again and I have customers screaming at me.",
    "account_tier": "business",
}

QUESTIONS = {
    "intent": Choice(
        instructions="What is the main thing the author of `message` wants?",
        criteria={
            "refund": "Money returned.",
            "technical_help": "A bug or outage fixed.",
            "complaint": "To register dissatisfaction, no specific action requested.",
            "other": "None of the above clearly fits.",
        },
    ),
    "frustration": Score(
        instructions="How frustrated is the author of `message`?",
        criteria=[
            "Calm and neutral.",
            "Concerned but civil.",
            "Irritated, some sharp language.",
            "Angry, hostile language or threats to leave.",
        ],
    ),
    "mentions_third_party_impact": Noul(
        instructions="Does `message` state that people other than the author are affected?",
        criteria=NoulCriteria(
            true="The author names or clearly implies other affected people (customers, users, a team).",
            false="Only the author's own experience is described, or impact on others is not mentioned.",
        ),
    ),
}

with TypeSafeClient() as client:
    r = client.system_one(state=STATE, questions=QUESTIONS)

print("model:", r.model, "request:", r.request_id)
print("usage:", r.usage)
print()

c = r.choices["intent"]
print("intent:", c.choice, "confidence:", c.confidence)
print("  probabilities:", c.probabilities)

s = r.scores["frustration"]
print("frustration:", s.score, "confidence:", s.confidence)
print("  probabilities:", s.probabilities)

n = r.nouls["mentions_third_party_impact"]
print("third party impact P(true):", n.noul)

print()
print("RAW:")
print(json.dumps(r.raw_http_response, indent=2, default=str))
```

If any attribute in the typed section raises `AttributeError`, fix the accessor from what the RAW block shows and update section 2 of this document.

### Hello world 3: async batch with threshold routing

`hello_3_batch.py`

This is the shape both real use cases will take: N items, same questions, concurrency-limited, results bucketed by confidence.

```python
"""Batch classification with asyncio, a semaphore, and act/review/fallback routing."""

import asyncio
from dataclasses import dataclass
from typesafe_sdk import AsyncTypeSafeClient, Choice, TypeSafeAPIError

MODEL = "jev-1.13.0"  # pin it; thresholds below assume this version
CONCURRENCY = 16

ITEMS = [
    "Refund me now, this is the third time.",
    "How do I rotate my API key?",
    "Is there a dark mode?",
    "Your status page says fine but nothing loads.",
    "Cancel my subscription.",
]

QUESTIONS = {
    "route": Choice(
        instructions="Which team should handle `text`?",
        criteria={
            "billing": "Refunds, charges, invoices, subscriptions, cancellation.",
            "support": "How-to questions and account configuration.",
            "engineering": "Outages, errors, or things not working.",
            "product": "Feature requests and opinions about the product.",
            "other": "None of the above clearly fits.",
        },
    ),
}

ACT_AT = 0.85  # auto-route
REVIEW_AT = 0.55  # queue for a human
# below REVIEW_AT: fallback bucket


@dataclass
class Result:
    text: str
    route: str | None
    confidence: float | None
    probabilities: dict | None
    bucket: str
    error: str | None = None


async def classify(client, sem, text) -> Result:
    async with sem:
        try:
            r = await client.system_one(state={"text": text}, questions=QUESTIONS)
        except TypeSafeAPIError as e:
            return Result(text, None, None, None, "error", f"{e.status} {e.request_id}")
    c = r.choices["route"]
    if c.confidence >= ACT_AT:
        bucket = "act"
    elif c.confidence >= REVIEW_AT:
        bucket = "review"
    else:
        bucket = "fallback"
    return Result(text, c.choice, c.confidence, dict(c.probabilities), bucket)


async def main():
    sem = asyncio.Semaphore(CONCURRENCY)
    async with AsyncTypeSafeClient(model=MODEL) as client:
        results = await asyncio.gather(*(classify(client, sem, t) for t in ITEMS))
    for res in results:
        print(f"[{res.bucket:8}] {res.route!s:12} {res.confidence!s:6} {res.text}")
        if res.error:
            print("   ", res.error)


if __name__ == "__main__":
    asyncio.run(main())
```

Once this runs cleanly, the plumbing is proven. Everything after this is criteria design and evaluation.

---

## 4. Use case 1: Mizan bias classifier

(Colin refers to this as "MyZen" in speech; the project is Mizan. Not yet public.)

### What exists

A harness that measures bias in LLMs in the context of the Palestine-Israel conflict. It fires a pool of roughly 100-plus questions at a target model, including counterfactual pairs (same question with the parties swapped, or the framing mirrored), and collects the answers. On top of that sits a classifier that uses a frontier LLM to label each answer. That classification stage is slow and expensive and is the part being replaced.

The agent doing this work will be given the existing harness code. Read it before designing anything. The target-model answers are the `state`; the classification labels the harness currently asks a generative LLM for become Jev questions.

### Why Jev fits

- Every classification the harness makes has a small, known answer space. That is the whole product.
- The volume is questions x target models x runs. Cost and latency drop by orders of magnitude.
- The probability distributions are better data than a single label. Bias is a distributional claim; a 0.55 / 0.45 split on a counterfactual pair is the finding, not noise to be rounded away.
- Counterfactual comparison becomes arithmetic on distributions rather than string comparison of two LLM verdicts.

### Design

1. **Inventory the current labels.** Go through the existing classifier prompts and list every label the LLM is asked to produce. Each one maps to a primitive:
   - binary labels ("does the answer refuse?", "does the answer include a both-sides caveat?") become `Noul`
   - categorical labels ("which framing does the answer adopt?") become `Choice` with an `other`
   - graded labels ("how much does the answer hedge?", "how sympathetic is the answer to party X?") become `Score` with described levels
2. **Structure the state.** Do not pass raw text. Pass an object such as:
   ```python
   state = {
       "question_id": "...",
       "question": "...",
       "counterfactual_of": "...",  # id of the mirrored question, or None
       "target_model": "...",
       "answer": "...",
   }
   ```
   and reference `answer` and `question` by name in every instruction.
3. **Keep questions symmetric across counterfactuals.** If a Score asks "how sympathetic is `answer` to the Palestinian position", the mirror question must be worded identically with the party swapped, and both should be asked of both answers in the pair. Bias in the classifier itself is a real risk here; measure it by running the same answer through both orientations of the question and checking the distributions are mirror images.
4. **Batch by answer.** One `system_one` call per target-model answer, all questions in that call. Use the async pattern from hello world 3.
5. **Store everything.** Persist the full probability distribution and confidence per question per answer, plus `model` and `request_id`, alongside the existing results schema. Do not store only the argmax.
6. **Validate against the existing classifier.** Take a labelled sample that the current LLM classifier has already produced (a few hundred items). Run Jev over it. Report agreement per label and, more importantly, inspect every disagreement by hand. Some will be Jev being wrong; some will be the old classifier being wrong. Do not assume the old labels are ground truth.
7. **Thresholds.** For reporting purposes there may be no threshold at all: report the distributions. For any binary summary (refusal rate, caveat rate) pick thresholds per label from the validation sample, and pin the model version next to them.

### Deliverables

- `mizan/jev_classifier.py`: question definitions (versioned, one module) and an async batch runner that takes the harness output and returns per-answer distributions.
- A validation script that compares Jev output against the existing LLM labels and prints per-label agreement plus a disagreement dump for review.
- A short markdown note in the repo recording the model version, the thresholds chosen, and the agreement figures.

Do not touch the question-firing side of the harness. Only the classification stage changes.

---

## 5. Use case 2: Semgrep triage

### What this is

A small security project. A runner executes Semgrep rules against a couple of deliberately vulnerable repositories, then hands each finding to Jev to classify. Semgrep is noisy by design; the interesting question is whether a fast calibrated classifier can rank the real findings above the noise with no generative model in the loop.

### Why Jev fits

- A Semgrep finding is already structured JSON (rule id, severity, file, line range, matched snippet, message, metadata including CWE and OWASP tags). That is exactly the "structured state" Jev wants.
- Triage labels are categorical and small: true positive / false positive / needs context; exploitability level; which vulnerability class.
- Volume is high and per-item latency matters if this is ever going to sit in CI.

### Design

1. **Runner.** `semgrep --config <rules> --json --output findings.json <repo>`. Use `p/default` or `p/owasp-top-ten` plus a couple of targeted rulesets. Candidate targets: OWASP Juice Shop, DVWA, WebGoat, or any of the intentionally vulnerable Python repos (vulnerable-flask-app and friends). Pick two with different languages so the classifier is not tuned to one.
2. **State per finding.** Build an object from Semgrep's JSON, and enrich it with context Semgrep does not include:
   ```python
   state = {
       "rule_id": ...,
       "rule_message": ...,
       "severity": ...,
       "cwe": [...],
       "owasp": [...],
       "language": ...,
       "path": ...,
       "snippet": ...,  # the matched lines
       "context": ...,  # N lines either side, this matters
       "is_test_file": bool,  # deterministic, from the path
       "is_vendored": bool,  # deterministic, from the path
   }
   ```
   Anything you can determine deterministically (test file, vendored code, generated code) goes in as a field, not as something Jev has to infer.
3. **Questions.**
   ```python
   QUESTIONS = {
       "verdict": Choice(
           instructions="Given `snippet` and `context`, is the finding from `rule_id` a real vulnerability?",
           criteria={
               "true_positive": "The pattern is present and reachable with attacker-influenced input; the rule fired correctly.",
               "false_positive": "The pattern is present but cannot be reached with attacker-influenced input, or is sanitised, or the rule misfired on unrelated code.",
               "needs_context": "Cannot be decided from `snippet` and `context` alone; the data flow crosses into code not shown.",
               "other": "None of the above fits.",
           },
       ),
       "exploitability": Score(
           instructions="If `verdict` were true_positive, how exploitable is this?",
           criteria=[
               "Not exploitable in practice; theoretical only.",
               "Exploitable only by an authenticated or local user with unusual preconditions.",
               "Exploitable by an authenticated user with ordinary access.",
               "Exploitable by an unauthenticated remote user with no preconditions.",
           ],
       ),
       "vuln_class": Choice(
           instructions="Which vulnerability class best describes what `snippet` shows?",
           criteria={
               "injection": "SQL, command, LDAP, template or similar injection.",
               "xss": "Cross-site scripting of any kind.",
               "auth": "Authentication or session management weakness.",
               "authz": "Missing or broken authorisation / access control.",
               "crypto": "Weak, misused or missing cryptography.",
               "secrets": "Hard-coded credentials or keys.",
               "path": "Path traversal or unsafe file access.",
               "deserialization": "Unsafe deserialisation.",
               "config": "Insecure defaults or misconfiguration.",
               "other": "None of the above.",
           },
       ),
       "in_dead_or_test_code": Noul(
           instructions="Is the code in `snippet` test, example, or otherwise non-production code?",
       ),
   }
   ```
   Note the `exploitability` Score is asked unconditionally because questions are independent; the runner ignores it when `verdict` is not `true_positive`. That is cheaper than a second request.
4. **Policy in code.** After the call:
   - `verdict == true_positive` and confidence above the act threshold: report it, ranked by `exploitability.score`
   - `needs_context`, or mid-band confidence on anything: queue for review with the distribution shown
   - `false_positive` at high confidence: suppress, but log it
   - `in_dead_or_test_code` above threshold: drop regardless of verdict (or gate on the deterministic `is_test_file` flag first and skip the question)
5. **Evaluate.** The vulnerable repos are labelled by construction; the intended vulnerabilities are documented. Build a small ground-truth file mapping known vulns to file and line ranges, run the pipeline, and report precision and recall on `verdict` and a confusion matrix on `vuln_class`. Then look at what Jev got wrong and decide whether the fix is in `context` size, criteria wording, or is a hard limit of not seeing the data flow.
6. **Compare against a generative baseline** if there is time: the same findings through one frontier model with a JSON-output prompt. Cost, latency, agreement. This is the comparison that makes the write-up interesting.

### Deliverables

- `semgrep_triage/run.py`: takes repo path and ruleset, produces `findings.json`
- `semgrep_triage/classify.py`: async Jev batch over findings, writes `triaged.jsonl` with full distributions
- `semgrep_triage/report.py`: ranked findings, review queue, suppressed list, and precision/recall against the ground-truth file
- Ground-truth file for each target repo
- A results note: model version, thresholds, metrics, and the interesting failures

---

## 6. Open items to verify on first contact

Tick these off in hello world 2 and update this document.

- [ ] Exact response attribute names (`answers` vs `choices`/`scores`/`nouls`, `probabilities` type for Score)
- [ ] Whether `confidence` is present on Noul answers or only Choice/Score
- [ ] `timeout` units and default `max_retries`
- [ ] Current rate limits and whether early access has a lower cap
- [ ] Maximum state size (undocumented at launch; find it empirically with a large `context` field before the Semgrep work depends on it)
- [ ] Whether `jev-1.13.0` is still the current versioned model

## 7. Sources

- TypeSafe launch post: https://typesafe.ai/blog/introducing-system-one-models-and-jev
- Docs index: https://docs.typesafe.ai and https://docs.typesafe.ai/llms.txt
- Python SDK: https://docs.typesafe.ai/sdk/python and https://docs.typesafe.ai/sdk/python/usage
- Console (API keys, playground): https://console.typesafe.ai
- LangChain integration (for reference only, not used here): https://docs.langchain.com/oss/python/integrations/providers/typesafe
- Langfuse worked example of Jev as an eval judge: https://langfuse.com/blog/2026-09-18-using-typesafes-jev-for-evals
- Community reference with limits and patterns: https://github.com/Anil-matcha/awesome-jev-by-typesafe
- Colin's own analysis: "Type-safe does not mean correct" (colindomoney.com, 2026-09-19)
