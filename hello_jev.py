"""Five silly examples of what Jev does, followed by some timing analysis.

Jev is not a chat model. You hand it a `state` (text or JSON) and a dictionary of typed
questions (Noul = yes/no probability, Choice = pick one of your options, Score = where on an
ordered rubric) and it returns typed answers with probability distributions. It never returns an
option you did not offer, and it never explains itself.

    uv run hello_jev.py                  # everything, ~45 API calls, well under a cent
    uv run hello_jev.py --repeats 3      # lighter timing section
    uv run hello_jev.py --skip-async     # no concurrency test

Needs TYPESAFE_API_KEY in the environment or in ./.env (see .env.example).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv
from typesafe_sdk import (
    AsyncTypeSafeClient,
    Choice,
    Noul,
    NoulCriteria,
    Score,
    TypeSafeAPIError,
    TypeSafeClient,
)

ROOT = Path(__file__).resolve().parent
SHAPE_PATH = ROOT / "docs" / "jev-response-shape.json"
PRICE_PER_M_INPUT = 0.042  # USD, launch pricing; output tokens are free

# --- timing bookkeeping ------------------------------------------------------------------------


@dataclass
class Call:
    label: str
    n_questions: int
    ms: float
    input_tokens: int | None
    model: str
    request_id: str | None
    server_ms: float | None  # x-envoy-upstream-service-time: time inside TypeSafe's edge


@dataclass
class Ledger:
    calls: list[Call] = field(default_factory=list)

    def timed(self, client: TypeSafeClient, label: str, state, questions, **kw):
        t0 = time.perf_counter()
        r = client.system_one(state=state, questions=questions, **kw)
        ms = (time.perf_counter() - t0) * 1000
        hdr = r.raw_http_response.headers.get("x-envoy-upstream-service-time")
        server_ms = float(hdr) if hdr else None
        self.calls.append(
            Call(label, len(questions), ms, r.usage.input_tokens, r.model, r.request_id, server_ms)
        )
        return r, ms


def bar(p: float, width: int = 20) -> str:
    n = round(p * width)
    return "█" * n + "░" * (width - n)


def h(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


# --- example 1: Noul --------------------------------------------------------------------------

FOODS = ["a hot dog", "a taco", "an ice cream sandwich", "a burrito", "a bowl of cereal"]

IS_SANDWICH = Noul(
    instructions="Is `food` a sandwich?",
    criteria=NoulCriteria(
        true="A filling held between or inside bread or a bread-like carrier, eaten by hand.",
        false="No bread-like carrier, or the carrier is not what makes the dish what it is.",
    ),
)


def example_1(client: TypeSafeClient, ledger: Ledger) -> None:
    h("1. Noul: is a hot dog a sandwich?  (one yes/no question, five foods, five calls)")
    print("A Noul returns P(yes). No verdict, no argument, just a number you can threshold.\n")
    for food in FOODS:
        r, ms = ledger.timed(client, "1 sandwich", {"food": food}, {"sandwich": IS_SANDWICH})
        p = r.nouls["sandwich"].noul
        print(f"  {food:24} {bar(p)} P(sandwich)={p:.2f}   {ms:5.0f} ms")
    print("\n  The ordering is the point: the model holds a graded belief and reports it.")


# --- example 2: Choice with an `other` --------------------------------------------------------

SNIPPETS = {
    "print('hello, world')": "python",
    "SELECT name FROM users WHERE id = 42;": "sql",
    "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.": "?",
}

WHICH_LANGUAGE = Choice(
    instructions="Which programming language is `code` written in?",
    criteria={
        "python": "Python.",
        "javascript": "JavaScript or TypeScript.",
        "sql": "Any SQL dialect.",
        "java": "Java.",
        "go": "Go.",
        "rust": "Rust.",
        "bash": "A POSIX shell.",
        "other": "None of the above, or not recognisable as a programming language.",
    },
)


def example_2(client: TypeSafeClient, ledger: Ledger) -> None:
    h("2. Choice: which language is this?  (eight options incl. `other`, three snippets)")
    print("A Choice can only answer with a key you supplied. `other` is where doubt goes.\n")
    for code, expected in SNIPPETS.items():
        r, ms = ledger.timed(client, "1 language", {"code": code}, {"lang": WHICH_LANGUAGE})
        a = r.choices["lang"]
        top = sorted(a.probabilities.items(), key=lambda kv: -kv[1])[:3]
        dist = "  ".join(f"{k}={v:.2f}" for k, v in top)
        print(
            f"  {code[:36]:36} (really: {expected:6}) -> {a.choice:10} "
            f"conf={a.confidence:.2f}  [{dist}]  {ms:4.0f} ms"
        )
    print("\n  The last one is Brainfuck. It lands in `other`, and usually with full confidence:")
    print("  `other` is a real answer, not a shrug. Leave it out and the mass has to go somewhere.")


# --- example 3: Score -------------------------------------------------------------------------

DISHES = [
    "Plain steamed rice with a little butter.",
    "Tikka masala, the mild one, extra cream.",
    "Ghost-pepper vindaloo, cooked by someone who believes you insulted their mother.",
]

SPICINESS = Score(
    instructions="How spicy is the dish described in `menu_item`?",
    criteria=[
        "No detectable heat at all.",
        "A gentle warmth; a child would eat it.",
        "Noticeably hot; most adults reach for water.",
        "Very hot; sweating, hiccups, regret the next morning.",
        "Weaponised; requires a waiver.",
    ],
)


def example_3(client: TypeSafeClient, ledger: Ledger) -> None:
    h("3. Score: how spicy is it?  (five described levels, three dishes)")
    print("A Score is a rubric. Levels are descriptions, not numbers. The score is probability-")
    print("weighted, so it can land between levels.\n")
    for dish in DISHES:
        r, ms = ledger.timed(client, "1 spice", {"menu_item": dish}, {"heat": SPICINESS})
        a = r.scores["heat"]
        print(f"  {dish[:58]:58}  score={a.score:.2f}/4  conf={a.confidence:.2f}  {ms:4.0f} ms")
        for level, p in sorted(a.probabilities.items()):
            print(f"      L{level} {bar(p, 12)} {p:.2f}  {a.legend[level]}")


# --- example 4: several questions, one call ---------------------------------------------------

JOKES = [
    "I told my wife she was drawing her eyebrows too high. She looked surprised.",
    "The quarterly figures are attached. Please review before Thursday.",
    "Why don't skeletons fight each other? They don't have the guts.",
]

JOKE_QUESTIONS = {
    "is_joke": Noul(instructions="Is `text` an attempt at a joke?"),
    "has_pun": Noul(
        instructions="Does `text` rely on a pun or a double meaning of a word or phrase?"
    ),
    "groan": Score(
        instructions="How bad is the joke in `text`, as a dad joke?",
        criteria=[
            "Not a joke.",
            "A small smile.",
            "An audible groan.",
            "Eye-roll, and someone leaves the room.",
        ],
    ),
    "kind": Choice(
        instructions="What kind of joke is `text`?",
        criteria={
            "pun": "Wordplay on a double meaning.",
            "anti_joke": "Sets up a joke and delivers a literal or mundane answer.",
            "observational": "Humour from everyday situations.",
            "other": "Not a joke, or none of the above.",
        },
    ),
}


def example_4(client: TypeSafeClient, ledger: Ledger) -> None:
    h("4. Mixed: rate the dad joke  (two Nouls, a Score and a Choice in ONE call, three texts)")
    print("Questions in a request are evaluated in parallel and in isolation. One round trip.\n")
    for text in JOKES:
        r, ms = ledger.timed(client, "4 jokes", {"text": text}, JOKE_QUESTIONS)
        n, c, s = r.nouls, r.choices, r.scores
        print(f"  {text[:60]:60}  {ms:4.0f} ms")
        print(
            f"      P(joke)={n['is_joke'].noul:.2f}  P(pun)={n['has_pun'].noul:.2f}  "
            f"groan={s['groan'].score:.2f}/3  kind={c['kind'].choice} ({c['kind'].confidence:.2f})"
        )
    print("\n  Note the middle one. A Score of ~0 and kind=other is how Jev says 'not applicable'.")


# --- example 5: fan-out over one state --------------------------------------------------------

RANSOM_NOTE = {
    "note": (
        "To the tall ones. The blue vase is gone and it is not coming back. "
        "I want the good tuna, not the one in gravy, and I want it at 5am. "
        "The dog knows what he did. Do not test me. - M."
    ),
    "found_on": "kitchen floor, next to a puddle",
}

NOTE_QUESTIONS = {
    "by_cat": Noul(instructions="Was `note` written by a cat?"),
    "by_dog": Noul(instructions="Was `note` written by a dog?"),
    "mentions_vase": Noul(instructions="Does `note` mention a vase?"),
    "threatens": Noul(instructions="Does `note` contain a threat, however vague?"),
    "demand": Choice(
        instructions="What is the main demand in `note`?",
        criteria={
            "food": "Specific food, served a specific way or time.",
            "attention": "Company, play, or being let in or out.",
            "revenge": "Punishment of a third party.",
            "money": "A ransom in currency.",
            "other": "None of the above.",
        },
    ),
    "menace": Score(
        instructions="How menacing is the tone of `note`?",
        criteria=["Friendly.", "Passive-aggressive.", "Openly threatening.", "Bond villain."],
    ),
    "urgency": Score(
        instructions="How time-sensitive is the demand in `note`?",
        criteria=["Whenever.", "Today.", "Right now, and it is already late."],
    ),
    "remorse": Score(
        instructions="How much remorse does the author of `note` show about the vase?",
        criteria=["None whatsoever.", "A little.", "Genuinely sorry."],
    ),
}


def example_5(client: TypeSafeClient, ledger: Ledger):
    h("5. Fan-out: the ransom note  (eight questions, one state, one call)")
    print("The pattern both real use cases take: throw every question you might want at one")
    print("state in a single request, then let ordinary code decide what matters.\n")
    print(f"  note: {RANSOM_NOTE['note']}\n")
    r, ms = ledger.timed(client, "8 note", RANSOM_NOTE, NOTE_QUESTIONS)
    for name, a in r.nouls.items():
        print(f"  {name:14} {bar(a.noul, 12)} P={a.noul:.2f}")
    d = r.choices["demand"]
    print(f"  {'demand':14} {d.choice:10} conf={d.confidence:.2f}  {d.probabilities}")
    for name in ("menace", "urgency", "remorse"):
        a = r.scores[name]
        top = max(a.probabilities, key=a.probabilities.get)
        print(f"  {name:14} {a.score:.2f}  conf={a.confidence:.2f}  '{a.legend[top]}'")
    print(f"\n  {ms:.0f} ms for all eight. Tokens in: {r.usage.input_tokens}.")
    print(f"  request_id={r.request_id}")
    return r


# --- timing -------------------------------------------------------------------------------------


def timing_questions_vs_latency(client: TypeSafeClient, ledger: Ledger, repeats: int) -> None:
    h(f"Timing A: does asking more questions cost more time?  ({repeats} repeats each)")
    one = {"by_cat": NOTE_QUESTIONS["by_cat"]}
    rows = []
    for label, qs in (("1 question", one), ("8 questions", NOTE_QUESTIONS)):
        samples = []
        for _ in range(repeats):
            _, ms = ledger.timed(client, f"timing {label}", RANSOM_NOTE, qs)
            samples.append(ms)
        rows.append((label, samples))
    print(f"  {'':14} {'min':>7} {'median':>7} {'max':>7}")
    for label, s in rows:
        print(f"  {label:14} {min(s):7.0f} {statistics.median(s):7.0f} {max(s):7.0f}   ms")
    one_med = statistics.median(rows[0][1])
    eight_med = statistics.median(rows[1][1])
    print(f"\n  8 questions vs 1: {eight_med / one_med:.2f}x the median latency.")


async def _burst(n: int, concurrency: int, model: str | None) -> tuple[list[float], float]:
    sem = asyncio.Semaphore(concurrency)
    lat: list[float] = []

    async def one(i: int) -> None:
        async with sem:
            t0 = time.perf_counter()
            await client.system_one(
                state={"food": FOODS[i % len(FOODS)]}, questions={"sandwich": IS_SANDWICH}
            )
            lat.append((time.perf_counter() - t0) * 1000)

    t0 = time.perf_counter()
    async with AsyncTypeSafeClient(model=model) as client:
        await asyncio.gather(*(one(i) for i in range(n)))
    return lat, (time.perf_counter() - t0) * 1000


def timing_concurrency(n: int, concurrency: int, model: str | None) -> None:
    h(f"Timing B: {n} calls sequentially vs {concurrency} at a time (async client)")
    seq_lat, seq_total = asyncio.run(_burst(n, 1, model))
    par_lat, par_total = asyncio.run(_burst(n, concurrency, model))
    print(
        f"  sequential : {seq_total:7.0f} ms total, median call {statistics.median(seq_lat):.0f} ms"
    )
    print(
        f"  concurrent : {par_total:7.0f} ms total, median call {statistics.median(par_lat):.0f} ms"
    )
    print(f"  speed-up   : {seq_total / par_total:.1f}x   ({n / (par_total / 1000):.0f} calls/s)")
    print("  Per-call latency barely moves under concurrency; the limit is requests per minute.")


def timing_summary(ledger: Ledger) -> None:
    h("Timing C: every synchronous call this run")
    ms = [c.ms for c in ledger.calls]
    ms_sorted = sorted(ms)
    p95 = ms_sorted[min(len(ms_sorted) - 1, int(0.95 * len(ms_sorted)))]
    tokens = sum(c.input_tokens or 0 for c in ledger.calls)
    print(
        f"  calls: {len(ms)}   min {min(ms):.0f}  median {statistics.median(ms):.0f}  "
        f"p95 {p95:.0f}  max {max(ms):.0f} ms"
    )
    server = [c.server_ms for c in ledger.calls if c.server_ms is not None]
    if server:
        srv = statistics.median(server)
        net = statistics.median(ms) - srv
        print(f"  server-side (x-envoy-upstream-service-time): median {srv:.0f} ms,")
        print(f"  so roughly {net:.0f} ms of the median call is network and TLS from here.")
    by_label: dict[str, list[float]] = {}
    for c in ledger.calls:
        by_label.setdefault(c.label, []).append(c.ms)
    for label, s in by_label.items():
        print(f"    {label:22} n={len(s):2}  median {statistics.median(s):5.0f} ms")
    print(
        f"\n  input tokens: {tokens}  ->  ${tokens / 1e6 * PRICE_PER_M_INPUT:.6f} at "
        f"${PRICE_PER_M_INPUT}/M (output is free)"
    )
    print(f"  model: {sorted({c.model for c in ledger.calls})}")


# --- main ---------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--repeats", type=int, default=5, help="repeats per arm in timing A")
    ap.add_argument("--burst", type=int, default=20, help="calls in timing B")
    ap.add_argument("--concurrency", type=int, default=8, help="parallel calls in timing B")
    ap.add_argument(
        "--model", default=None, help="pin a model, e.g. jev-1.13.0 (default: env or jev-latest)"
    )
    ap.add_argument("--skip-async", action="store_true")
    args = ap.parse_args()

    load_dotenv(ROOT / ".env")
    if not os.environ.get("TYPESAFE_API_KEY"):
        print("TYPESAFE_API_KEY is not set. Put it in .env (see .env.example) or export it.")
        return 2

    ledger = Ledger()
    with TypeSafeClient(model=args.model) as client:
        models = client.models.list().models
        print("Available models:", ", ".join(f"{m.name} ({m.release_date})" for m in models))
        try:
            example_1(client, ledger)
            example_2(client, ledger)
            example_3(client, ledger)
            example_4(client, ledger)
            note = example_5(client, ledger)
            timing_questions_vs_latency(client, ledger, args.repeats)
        except TypeSafeAPIError as e:
            print(
                f"\nAPI error {e.status_code if hasattr(e, 'status_code') else ''}: {e} "
                f"(request_id={getattr(e, 'request_id', None)})"
            )
            return 1

    if not args.skip_async:
        timing_concurrency(args.burst, args.concurrency, args.model)
    timing_summary(ledger)

    # Keep one raw payload on disk: it is the ground truth for the SDK attribute names.
    SHAPE_PATH.parent.mkdir(exist_ok=True)
    SHAPE_PATH.write_text(json.dumps(note.raw_http_response.json(), indent=2) + "\n")
    print(f"\nRaw response of example 5 written to {SHAPE_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
