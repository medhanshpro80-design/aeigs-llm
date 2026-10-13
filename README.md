# AegisLLM — AI Model & LLM Application Security Monitor

A security gateway that sits between users and an LLM application, plus a monitoring dashboard.
It checks every interaction at four points, applies security policies, logs each decision to a
tamper-evident audit trail, and turns what it sees into guardrail recommendations.

```
 user ─▶ ① INPUT ─▶ ② RETRIEVAL ─▶ LLM ─▶ ③ TOOL CALLS ─▶ ④ OUTPUT ─▶ user
         injection    provenance           least-privilege   leakage / PII
         jailbreaks   indirect injection   egress control    exfil channels
         abuse/rate   access control       taint tracking    redaction
              └──────────── policy engine (block / quarantine / redact / flag) ───────────┘
                                         │
                       hash-chained audit log ─▶ dashboard · red team · recommendations
```

## Run it

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/python seed.py          # 24h of demo traffic + one red-team run
./.venv/bin/uvicorn server:app --port 8000
```

Open http://localhost:8000. API docs: http://localhost:8000/docs.
No API keys or internet connection needed. Everything runs locally, so the demo can't break because of venue Wi-Fi.

## How it maps to the problem statement

| Objective | Where |
|---|---|
| 1. Evaluate prompts & outputs against security policies | `aegis/policy.py`: 12 declarative rules (category × stage × severity → action), monitor vs enforce mode, editable in the **Policies** tab |
| 2. Detect injection & data-exfiltration patterns | `aegis/detectors.py`: 12 injection rules incl. leetspeak, zero-width chars, base64 payloads, chat-template delimiters, hidden HTML; PII/secret detection (cards via Luhn, Aadhaar, PAN, SSN, AWS/API keys, JWTs, DB URIs); markdown-image beacons, data-carrying URLs, XSS; system-prompt leakage via canary token + n-gram overlap |
| 3. Monitor tool permissions & retrieval provenance | `aegis/monitors.py`: tool registry with role permissions, ownership scoping (cross-tenant), recipient/egress allowlists, read-only SQL, refund limits, human approval, and **taint tracking** (high-risk tool calls after untrusted content entered the context). Sources are checked for trust level, SHA-256 integrity (tampering), classification vs user clearance, and staleness |
| 4. Run adversarial test suites | `aegis/redteam.py`: 28 attacks across 9 OWASP categories + 8 benign prompts. Each attack runs with guardrails off and on, measuring attack success rate, detection rate, false positive rate, and which stage stopped it |
| 5. Log decisions for audit | `aegis/audit.py`: SQLite where every event stores the SHA-256 of the previous one. `verify` finds any edited or deleted row. Payloads are redacted before storage, and the log exports as JSONL |

| Expected outcome | Where |
|---|---|
| Visibility into AI-specific threats | **Overview**: KPIs, hourly timeline, OWASP LLM Top 10 breakdown, top rules, riskiest users |
| Earlier detection of unsafe interactions | Checks run at four stages, so most attacks are stopped before the model answers (input/retrieval/tool). The output stage is the last line of defence |
| Traceable security events | Every request has a `trace_id` that links its stage events. Click any event to see its full trace |
| Actionable guardrail recommendations | **Recommendations**: generated from the audit log and red-team gaps, ranked, OWASP-mapped, some with a one-click fix |

## Demo script (≈5 minutes)

1. **Overview** (30s). "This is 24 hours of traffic on a customer-support copilot. Around 5–7 hours ago one customer launched an attack campaign. Every threat is mapped to the OWASP LLM Top 10."
2. **Live Playground** (2 min). Tick *compare both* so each prompt runs with and without enforcement.
   - **Indirect (RAG)**: an innocent question pulls in a forum post with a hidden HTML comment. Without Aegis the model quietly runs `send_email` and sends the customer's card to an attacker, and the reply looks normal. With Aegis the document is quarantined at retrieval.
   - **Poisoned doc**: a document modified after ingestion. Its hash no longer matches, so it is quarantined. Without Aegis the reply includes an invisible image beacon that leaks base64-encoded PII.
   - **Paraphrased leak**: no input rule catches it, but the system-prompt canary catches it at output. That's defence in depth.
   - **Cross-tenant / Excessive agency / SSRF**: the tool-permission monitor blocks these.
3. **Red Team** (1 min). Click *Run*. 96% of attacks cause harm without guardrails, 0% with them, 0% false positives. The chart shows which stage stopped each attack.
4. **Audit Log** (1 min). Click *Verify chain* → intact. Then *Simulate tampering*, which acts like an insider changing a "block" to "allow" directly in the DB. Verify again → **broken at row N**. Use *Reset demo data* to restore.
5. **Recommendations** (30s). For example: "remove the community forum from the index", "move secrets out of the system prompt and rotate STAFF50", "take tool authorization from the session, not the model".
6. **Integrate** (optional). Under Tools & Sources, *Try it* calls `POST /api/evaluate`, which works with any LLM app.

## Honest limitations / next steps (judges will ask)

- Detection is rule-based (fast, explainable, ~1 ms per request). Next step: add an LLM-judge or fine-tuned classifier for paraphrased attacks. The red team's "caught late" metric shows where the regex rules fall short.
- The demo app's model is a **deterministic simulator of a naively obedient LLM**, so attacks reproduce reliably on stage. To use a real model (Claude, GPT, Llama), replace `VulnerableLLM` in `aegis/demo_app.py` or call `/api/evaluate` from your app.
- State is single-node SQLite and in-memory. For production: Postgres, a streaming pipeline, SIEM export (Splunk/Sentinel via the JSONL export), and an SDK/sidecar proxy.

## Layout

```
server.py            FastAPI app (API + dashboard)
seed.py              generates demo history
aegis/detectors.py   injection, PII/secrets, exfiltration, leakage
aegis/monitors.py    tool permissions + retrieval provenance
aegis/policy.py      policy rules and decisions
aegis/engine.py      the 4-stage gateway pipeline + /evaluate
aegis/audit.py       hash-chained audit log
aegis/redteam.py     adversarial test suite
aegis/insights.py    stats + recommendations
aegis/demo_app.py    vulnerable "Acme Support Copilot" (RAG + tools)
static/              dashboard (vanilla JS, no build step)
```
