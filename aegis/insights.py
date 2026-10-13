"""Dashboard analytics and actionable guardrail recommendations."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .detectors import OWASP, SEVERITY_SCORE
from .monitors import SOURCE_REGISTRY, TOOL_REGISTRY


def stats(events: list[dict], hours: int = 24) -> dict:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    ev = [e for e in events if datetime.fromisoformat(e["ts"]) >= since]
    traces = {e["trace_id"] for e in ev}
    findings = [f for e in ev for f in (e["findings"] or [])]

    # an interaction (trace) takes its worst decision
    rank = ["allow", "flag", "quarantine", "redact", "block"]
    trace_dec: dict[str, str] = {}
    for e in ev:
        cur = trace_dec.get(e["trace_id"], "allow")
        d = e["decision"]
        if e["mode"] == "monitor" and d != "allow":
            d = "flag"  # detected but not enforced
        trace_dec[e["trace_id"]] = max(cur, d, key=rank.index)
    dec = Counter(trace_dec.values())

    buckets = defaultdict(lambda: {"allow": 0, "flag": 0, "blocked": 0})
    seen = set()
    for e in sorted(ev, key=lambda x: x["ts"]):
        if e["trace_id"] in seen:
            continue
        seen.add(e["trace_id"])
        t = datetime.fromisoformat(e["ts"]).replace(minute=0, second=0, microsecond=0)
        d = trace_dec[e["trace_id"]]
        buckets[t.isoformat()]["blocked" if d in ("block", "quarantine", "redact") else d] += 1
    timeline = []
    for i in range(hours, -1, -1):
        t = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0).isoformat()
        timeline.append({"t": t, **buckets.get(t, {"allow": 0, "flag": 0, "blocked": 0})})

    users = defaultdict(lambda: {"events": 0, "violations": 0, "max_risk": 0, "role": ""})
    for e in ev:
        u = users[e["user_id"]]
        u["events"] += 1
        u["role"] = e["role"]
        u["max_risk"] = max(u["max_risk"], e["risk"])
        u["violations"] += e["decision"] == "block"
    top_users = sorted(({"user_id": k, **v} for k, v in users.items()), key=lambda x: (-x["violations"], -x["max_risk"]))[:8]

    rules = Counter((f["rule"], f["message"].split(":")[0]) for f in findings)
    owasp = Counter(f["owasp"] for f in findings if f.get("owasp"))
    return {
        "window_hours": hours,
        "interactions": len(traces),
        "events": len(ev),
        "findings": len(findings),
        "decisions": {k: dec.get(k, 0) for k in rank},
        "threat_rate": round(sum(dec[k] for k in ("block", "quarantine", "redact", "flag")) / (len(traces) or 1), 3),
        "by_category": dict(Counter(f["category"] for f in findings).most_common()),
        "by_severity": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_SCORE},
        "by_stage": dict(Counter(e["stage"] for e in ev if e["decision"] != "allow")),
        "owasp": [{"id": k, "name": OWASP.get(k, ""), "count": v} for k, v in sorted(owasp.items())],
        "top_rules": [{"rule": r, "message": m, "count": c} for (r, m), c in rules.most_common(8)],
        "top_users": top_users,
        "timeline": timeline,
        "recent_critical": [
            {k: e[k] for k in ("id", "ts", "trace_id", "user_id", "stage", "decision", "risk", "summary")}
            | {"top": max(e["findings"], key=lambda f: SEVERITY_SCORE[f["severity"]])["message"]}
            for e in sorted(ev, key=lambda x: x["ts"], reverse=True)
            if e["findings"] and e["risk"] >= 60][:8],
    }


def recommendations(events: list[dict], policy: dict, last_run: dict | None) -> list[dict]:
    findings = [(e, f) for e in events for f in (e["findings"] or [])]
    by_rule = defaultdict(list)
    for e, f in findings:
        by_rule[f["rule"]].append((e, f))
    recs = []

    def add(priority, title, detail, owasp, evidence, action=None):
        recs.append({"priority": priority, "title": title, "detail": detail, "owasp": owasp,
                     "owasp_name": OWASP.get(owasp, ""), "evidence": evidence, "action": action})

    high = [f for _, f in findings if SEVERITY_SCORE[f["severity"]] >= 60]
    if policy["mode"] == "monitor" and high:
        add("critical", "Switch the gateway from monitor to enforce mode",
            f"{len(high)} high/critical findings were only logged, not blocked.", "LLM01", len(high),
            {"type": "set_mode", "value": "enforce", "label": "Enable enforce mode"})

    indirect = [(e, f) for e, f in findings if f["category"] == "injection" and f["stage"] == "retrieval"]
    if indirect:
        srcs = Counter(f["meta"].get("source") for _, f in indirect)
        src, n = srcs.most_common(1)[0]
        add("critical", f"Remove or sanitise '{src}' in the retrieval index",
            f"{n} indirect prompt injections came from this source. Strip HTML comments/hidden text at ingestion, "
            "and wrap retrieved text in delimiters marked as untrusted data (spotlighting).", "LLM01", n,
            {"type": "untrust_source", "value": src, "label": "Mark source untrusted"}
            if SOURCE_REGISTRY.get(src, {}).get("trust") != "untrusted" else None)

    if by_rule["PROV-003"]:
        docs = sorted({f["meta"].get("doc_id") for _, f in by_rule["PROV-003"]})
        add("critical", "Re-ingest tampered documents and sign the ingestion pipeline",
            f"Hash mismatch on {', '.join(docs)}: content changed after approval. Require signed, hashed ingestion "
            "and alert on drift.", "LLM04", len(by_rule["PROV-003"]))
    if by_rule["PROV-001"]:
        srcs = sorted({f["meta"].get("source") for _, f in by_rule["PROV-001"]})
        add("medium", "Register or remove unknown retrieval sources",
            f"Documents served from unregistered sources: {', '.join(srcs)}.", "LLM04", len(by_rule["PROV-001"]))
    if by_rule["PROV-004"]:
        add("high", "Filter documents by the user's access level before retrieval",
            "Confidential documents reached sessions with lower clearance. Filter the vector store by role and "
            "classification so the model never sees them.", "LLM08", len(by_rule["PROV-004"]))

    if by_rule["TOOL-010"]:
        add("critical", "Disable high-risk tools when untrusted content is in context",
            "The model tried high-risk tools after it had read injected or untrusted content. Separate untrusted "
            "content from tool access (dual-LLM / plan-then-execute pattern).", "LLM06", len(by_rule["TOOL-010"]))
    exfil_tools = by_rule["TOOL-004"] + by_rule["TOOL-005"] + by_rule["TOOL-006"]
    if exfil_tools:
        add("high", "Lock outbound tool traffic to approved domains, with human approval",
            f"{len(exfil_tools)} attempts to send data to external recipients/hosts via send_email/http_fetch.",
            "LLM06", len(exfil_tools))
    if by_rule["TOOL-003"]:
        add("high", "Take tool authorization from the session, not from the model",
            "The model passed other customers' IDs to data tools. Read customer_id from the authenticated "
            "session on the server side.", "LLM02", len(by_rule["TOOL-003"]))
    if by_rule["TOOL-002"]:
        tools = Counter(f["meta"].get("tool") for _, f in by_rule["TOOL-002"])
        add("medium", "Only expose tools the user's role is allowed to call",
            "The model attempted privileged tools: " + ", ".join(f"{t} ×{n}" for t, n in tools.most_common()) +
            ". Don't offer tools above the user's role in the function list at all.", "LLM06",
            len(by_rule["TOOL-002"]))

    leaks = by_rule["LEAK-001"] + by_rule["LEAK-002"]
    if leaks:
        add("high", "Move secrets out of the system prompt and rotate them",
            "The system prompt leaked, and it contains a discount code and an internal email. Assume the "
            "prompt is public: rotate STAFF50-ACME and keep secrets in server-side tools.", "LLM07", len(leaks))
    pii_out = [f for _, f in findings if f["category"] == "sensitive_data" and f["stage"] == "output"
               and SEVERITY_SCORE[f["severity"]] >= 30]
    if pii_out:
        add("high", "Mask sensitive fields in tool responses",
            f"{len(pii_out)} sensitive values (cards, IDs) reached the model's output. Return only the last 4 digits "
            "from get_customer_record so the model never sees full PANs.", "LLM02", len(pii_out))
    if by_rule["EXF-001"] or by_rule["EXF-004"]:
        n = len(by_rule["EXF-001"]) + len(by_rule["EXF-004"])
        add("high", "Lock down markdown/HTML rendering in the chat UI",
            "Outputs contained external image beacons or scripts. Use a CSP that only loads images from "
            "allowlisted CDNs, and sanitise HTML before rendering.", "LLM05", n)

    offenders = Counter(e["user_id"] for e in events if e["decision"] == "block" and e["source"] != "redteam")
    bad = [(u, n) for u, n in offenders.most_common(3) if n >= 3]
    if bad:
        add("medium", "Investigate repeat offenders",
            "Users with repeated blocks: " + ", ".join(f"{u} ({n})" for u, n in bad) +
            ". Consider stricter rate limits or suspending their sessions.", "LLM10", sum(n for _, n in bad))

    disabled = [r for r in policy["rules"] if not r["enabled"]]
    for r in disabled:
        add("medium", f"Re-enable policy {r['id']}", f"'{r['name']}' is disabled.", "LLM01", 0,
            {"type": "enable_rule", "value": r["id"], "label": "Enable rule"})

    if last_run:
        s = last_run["summary"]
        late = set(s.get("late_catches", [])) | set(s.get("missed", []))
        missed = [r for r in last_run["results"] if r["id"] in late]
        if missed:
            add("medium", f"Close detection gaps found by the red team ({len(missed)} attacks got past the input filters)",
                "Only caught at the output stage, or not at all: " + "; ".join(f"{r['id']} {r['category']}" for r in missed[:4]) +
                ". Add an LLM-based classifier (e.g. a judge model) on top of the regex rules to catch paraphrased "
                "attacks.", "LLM01", len(missed))
        if s["guarded_asr"] > 0:
            add("high", f"{s['guarded_asr']:.0%} of attacks still succeed with guardrails on",
                "See the Red Team tab for the cases that got through.", "LLM01",
                round(s["guarded_asr"] * s["attacks"]))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recs.sort(key=lambda r: (order[r["priority"]], -r["evidence"]))
    return recs


def inventory() -> dict:
    return {"tools": [{"name": k, **v} for k, v in TOOL_REGISTRY.items()],
            "sources": [{"source": k, **v} for k, v in SOURCE_REGISTRY.items()]}
