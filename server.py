"""AegisLLM — AI Model & LLM Application Security Monitor (API + dashboard)."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from aegis import insights, redteam
from aegis.audit import AuditLog
from aegis.demo_app import CUSTOMERS, KB, SYSTEM_PROMPT
from aegis.engine import Gateway
from aegis.monitors import SOURCE_REGISTRY
from aegis.policy import PolicyStore

ROOT = Path(__file__).resolve().parent
app = FastAPI(title="AegisLLM Security Monitor", version="0.1",
              description="Security gateway and monitor for LLM applications: prompt injection, data leakage, "
                          "tool permissions, retrieval provenance, red teaming and tamper-evident audit.")
audit = AuditLog()
policy = PolicyStore()
gateway = Gateway(audit, policy)


class ChatIn(BaseModel):
    message: str
    user_id: str = "C-1001"
    role: str = "customer"
    mode: str | None = None
    approved: bool = False


@app.post("/api/chat", tags=["demo app"], summary="Send a message to the guarded demo app (Acme Support Copilot)")
def chat(body: ChatIn):
    return gateway.chat(body.message, user_id=body.user_id, role=body.role, mode=body.mode, approved=body.approved)


@app.post("/api/evaluate", tags=["gateway"], summary="Evaluate any LLM interaction (bring your own model)")
def evaluate(body: dict):
    """Pass any of: `prompt`, `documents` [{id, source, content, sha256}], `tool_calls` [{name, args}],
    `output`, `system_prompt`, `canary`, plus `user_id`, `role`, `app`. Returns a decision for each stage."""
    return gateway.evaluate(body)


@app.get("/api/events", tags=["audit"])
def events(limit: int = 200, decision: str | None = None, stage: str | None = None, category: str | None = None,
           user_id: str | None = None, trace_id: str | None = None, q: str | None = None, include_redteam: bool = True):
    rows = audit.query(limit=limit, decision=decision, stage=stage, category=category, user_id=user_id,
                       trace_id=trace_id, q=q)
    return rows if include_redteam else [r for r in rows if r["source"] != "redteam"]


@app.get("/api/stats", tags=["monitoring"])
def stats(hours: int = 24, include_redteam: bool = False):
    ev = audit.all()
    if not include_redteam:
        ev = [e for e in ev if e["source"] != "redteam"]
    return insights.stats(ev, hours) | {"mode": policy.mode}


@app.get("/api/recommendations", tags=["monitoring"])
def recommendations():
    runs = audit.runs(1)
    return insights.recommendations(audit.all(), policy.policy, runs[0] if runs else None)


@app.post("/api/recommendations/apply", tags=["monitoring"])
def apply_recommendation(action: dict):
    t, v = action.get("type"), action.get("value")
    if t == "set_mode":
        policy.save({"mode": v})
    elif t == "enable_rule":
        for r in policy.policy["rules"]:
            if r["id"] == v:
                r["enabled"] = True
        policy.save({})
    elif t == "untrust_source":
        if v in SOURCE_REGISTRY:
            SOURCE_REGISTRY[v]["trust"] = "untrusted"
    else:
        raise HTTPException(400, "unknown action")
    return {"ok": True}


@app.get("/api/policy", tags=["policy"])
def get_policy():
    return policy.policy


@app.put("/api/policy", tags=["policy"])
def put_policy(body: dict):
    policy.save(body)
    return policy.policy


@app.post("/api/policy/reset", tags=["policy"])
def reset_policy():
    policy.reset()
    return policy.policy


@app.post("/api/redteam/run", tags=["red team"])
def run_redteam():
    return redteam.run_suite(gateway)


@app.get("/api/redteam/runs", tags=["red team"])
def redteam_runs(limit: int = 5):
    return audit.runs(limit)


@app.get("/api/redteam/cases", tags=["red team"])
def redteam_cases():
    return {"attacks": redteam.CASES, "benign": redteam.BENIGN}


@app.get("/api/audit/verify", tags=["audit"])
def verify():
    return audit.verify()


@app.post("/api/audit/tamper-demo", tags=["audit"], summary="DEMO: silently edit a logged decision")
def tamper():
    return audit.tamper_demo()


@app.get("/api/audit/export", tags=["audit"], response_class=PlainTextResponse)
def export():
    return "\n".join(json.dumps(e) for e in audit.all())


@app.post("/api/reset", tags=["admin"], summary="Wipe the audit log and reseed demo data")
def reset(seed: bool = True):
    audit.reset()
    gateway.abuse.reset()
    policy.reset()
    if seed:
        from seed import seed_history
        seed_history(gateway)
        redteam.run_suite(gateway)
    return {"ok": True, "events": len(audit.all())}


@app.get("/api/inventory", tags=["monitoring"])
def inventory():
    inv = insights.inventory()
    inv["documents"] = [{k: d[k] for k in ("id", "source", "title", "ingested_at")} for d in KB]
    inv["app"] = {"name": "acme-support-copilot", "model": gateway.llm.name, "system_prompt": SYSTEM_PROMPT,
                  "users": [{"user_id": k, "name": v["name"]} for k, v in CUSTOMERS.items()]}
    return inv


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(ROOT / "static" / "index.html")
