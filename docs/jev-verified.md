# Jev: verified on first contact (2026-09-20)

Resolves the **VERIFY** items in `jev-handoff.md` §2 and §6. Source: `hello_jev.py` against the live
API with `typesafe-sdk` 0.7.0 (pydantic-based, released 2026-09-18). Raw payload of an eight-question
call is in `jev-response-shape.json`.

| Item | Result |
|---|---|
| Response attribute names | `response.answers` is the raw dict; `response.nouls / .choices / .scores` are typed views over it. `response.model`, `response.usage` (`input_tokens`, `output_tokens`), `response.request_id`, `response.raw_http_response` (an httpx `Response`; `.json()` gives the payload) all exist. |
| Noul answer | `.noul` only (P(true)). **No `confidence` on Noul**; only Choice and Score have it. |
| Score answer | `.score` (float, probability-weighted), `.confidence`, `.probabilities` is `dict[int, float]` keyed by level index, plus `.legend: dict[int, str]` mapping index to your level text. |
| Choice answer | `.choice`, `.confidence`, `.probabilities: dict[str, float]` over your keys. |
| `timeout` units | Seconds, float (or an `httpx.Timeout`). Default `10.0` on the client. |
| Retries | `RetryPolicy(max_retries=2, backoff_initial=0.5, backoff_max=5.0, backoff_jitter=0.25, respect_retry_after=True, timeout=30.0)` is the default; pass `retry=` on the client or per call. |
| Client construction | `TypeSafeClient(api_key, model, retry, timeout, headers, transport, http_client, base_url)`. `client.models.list()` (not `client.models()`) lists models. |
| Current model | `jev-latest` resolves to **`jev-1.13.0`** (response `model` field). `jev-preview` also exists ("should be better in most ways"). Pin `jev-1.13.0` wherever thresholds live. |
| Env vars | `TYPESAFE_API_KEY`, `TYPESAFE_BASE_URL` (default `https://api.typesafe.ai`), `TYPESAFE_DEFAULT_MODEL` (default `jev-latest`), `TYPESAFE_LOG_LEVEL`. |
| Latency (from London, 2026-09-20) | Sync calls: median ~310 ms wall, of which ~130 ms is server time (`x-envoy-upstream-service-time` header); the rest is network and TLS. 1 vs 8 questions on the same state: 253 vs 313 ms median (1.24x). |
| Concurrency | 20 calls at concurrency 8: 4.6x speed-up over sequential, ~15 calls/s, per-call latency unchanged. No 429s. |
| Rate limits | **Not verified numerically.** No rate-limit headers in responses. Handoff figure (~1,200 rpm) not contradicted at 15 calls/s. |
| Max state size | **Not tested.** Do this with a real Semgrep `context` field before phase 2 depends on it. |
| Cost | 25 sync calls, 11,533 input tokens, $0.0005 at $0.042/M. Output tokens are billed as free. |

Behaviour worth remembering from the silly examples:

- Noul on graded questions gives graded numbers: hot dog 0.79, ice cream sandwich 0.75, burrito 0.46, taco 0.39, cereal 0.01 for "is `food` a sandwich?".
- `other` in a Choice is a real answer. Brainfuck went to `other` with confidence 1.00.
- A Score on inapplicable input collapses to level 0 with high confidence (a business email scored 0.01/3 as a dad joke, `kind=other` at 1.00). That is the "not applicable" signal; there is no null.
- Confidence is derived from the distribution (peaked = high), so a Score that legitimately sits between two levels (menace 1.59) reports confidence ~0.58. Mid confidence is not always doubt about the input; sometimes the rubric has no level for it.
