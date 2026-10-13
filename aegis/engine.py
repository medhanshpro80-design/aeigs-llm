"""Security gateway: runs every interaction through input -> retrieval -> tool -> output checks."""
from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque

from . import demo_app
from .audit import AuditLog
from .detectors import (Finding, detect_exfiltration, detect_injection, detect_leakage,
                        detect_sensitive, injection_score, redact)
from .monitors import check_document, check_tool_call
from .policy import PolicyStore, risk_score

REFUSAL = "⚠️ This request was blocked by the AI security policy. If you think this is a mistake, contact support."


class AbuseTracker:
    """Sliding-window rate limiting and repeat-offender detection (model abuse / LLM10)."""

    def __init__(self):
        self.requests = defaultdict(deque)
        self.violations = defaultdict(deque)
        self.last_prompts = defaultdict(lambda: deque(maxlen=5))

    def check(self, user_id: str, prompt: str, policy: dict) -> list[Finding]:
        now = time.time()
        f = []
        rq = self.requests[user_id]
        rq.append(now)
        while rq and now - rq[0] > 60:
            rq.popleft()
        if len(rq) > policy["rate_limit_per_min"]:
            f.append(Finding("abuse", "ABUSE-001", "high",
                             f"Rate limit exceeded: {len(rq)} requests/min (limit {policy['rate_limit_per_min']})",
                             "input", "", "LLM10"))
        if len(prompt) > policy["max_prompt_chars"]:
            f.append(Finding("abuse", "ABUSE-002", "high" if len(prompt) > 2 * policy["max_prompt_chars"] else "medium",
                             f"Oversized prompt ({len(prompt)} chars) — resource exhaustion / context stuffing",
                             "input", "", "LLM10"))
        vq = self.violations[user_id]
        while vq and now - vq[0] > 600:
            vq.popleft()
        if len(vq) >= policy["block_user_after_violations"]:
            f.append(Finding("abuse", "ABUSE-003", "high",
                             f"User temporarily blocked: {len(vq)} policy violations in 10 minutes",
                             "input", "", "LLM10"))
        if list(self.last_prompts[user_id]).count(prompt) >= 3:
            f.append(Finding("abuse", "ABUSE-004", "low", "Repeated identical prompt (automated probing)",
                             "input", prompt[:60], "LLM10"))
        self.last_prompts[user_id].append(prompt)
        return f

    def violation(self, user_id: str):
        self.violations[user_id].append(time.time())

    def reset(self):
        self.__init__()


class Gateway:
    def __init__(self, audit: AuditLog, policy: PolicyStore):
        self.audit = audit
        self.policy = policy
        self.abuse = AbuseTracker()
        self.llm = demo_app.VulnerableLLM()

    # ------------------------------------------------------------------ helpers
    def _log(self, base: dict, stage: str, decision: str, findings: list[Finding], policies: list[str],
             summary: str, payload: dict, ts=None):
        return self.audit.log(
            trace_id=base["trace_id"], session_id=base["session_id"], user_id=base["user_id"], role=base["role"],
            app=base["app"], stage=stage, decision=decision, risk=risk_score(findings), mode=base["mode"],
            summary=summary, findings=[f.to_dict() for f in findings], policies=policies, payload=payload,
            source=base.get("source", "gateway"), ts=ts)

    def _enforce(self, mode: str, action: str) -> bool:
        return mode == "enforce" and action in ("block", "quarantine", "redact")

    # ------------------------------------------------------------------ demo-app chat pipeline
    def chat(self, message: str, user_id: str = "C-1001", role: str = "customer", session_id: str | None = None,
             mode: str | None = None, approved: bool = False, source: str = "gateway", ts=None) -> dict:
        mode = mode or self.policy.mode
        p = self.policy.policy
        base = {"trace_id": "tr-" + uuid.uuid4().hex[:10], "session_id": session_id or "s-" + user_id,
                "user_id": user_id, "role": role, "app": "acme-support-copilot", "mode": mode, "source": source}
        ctx = {"user_id": user_id, "role": role, "approved": approved, "tainted": False, "tainted_by": []}
        stages, all_findings = [], []
        t0 = time.perf_counter()

        # 1. INPUT ------------------------------------------------------------
        f_in = self.abuse.check(user_id, message, p) + detect_injection(message, "input") + \
            detect_sensitive(message, "input")
        act_in, pol_in = self.policy.decide(f_in, "input")
        stages.append({"stage": "input", "decision": act_in, "findings": [f.to_dict() for f in f_in],
                       "policies": pol_in, "injection_score": injection_score(f_in)})
        self._log(base, "input", act_in, f_in, pol_in, f"User prompt ({len(message)} chars)",
                  {"prompt": redact(message)[0]}, ts)
        all_findings += f_in
        if any(f.category == "injection" for f in f_in):
            ctx["tainted"] = True
            ctx["tainted_by"].append("user_prompt")
        if act_in == "block":
            self.abuse.violation(user_id)
        if self._enforce(mode, act_in):
            return self._finish(base, stages, all_findings, REFUSAL, "block", t0, ts)

        # 2. RETRIEVAL --------------------------------------------------------
        docs = demo_app.search_kb(message)
        kept, doc_reports = [], []
        f_ret_all = []
        for d in docs:
            f_d = check_document(d, ctx)
            act_d, pol_d = self.policy.decide(f_d, "retrieval")
            quarantined = self._enforce(mode, act_d)
            doc_reports.append({"id": d["id"], "title": d["title"], "source": d["source"], "decision": act_d,
                                "quarantined": quarantined, "findings": [f.to_dict() for f in f_d], "policies": pol_d})
            if not quarantined:
                kept.append(d)
                if any(f.category == "injection" for f in f_d):
                    ctx["tainted"] = True
                    ctx["tainted_by"].append(d["id"])
            f_ret_all += f_d
        act_ret = max((r["decision"] for r in doc_reports),
                      key=lambda a: ["allow", "flag", "quarantine", "redact", "block"].index(a), default="allow")
        pol_ret = sorted({x for r in doc_reports for x in r["policies"]})
        stages.append({"stage": "retrieval", "decision": act_ret, "documents": doc_reports,
                       "findings": [f.to_dict() for f in f_ret_all], "policies": pol_ret})
        self._log(base, "retrieval", act_ret, f_ret_all, pol_ret,
                  f"{len(docs)} docs retrieved, {len(docs) - len(kept)} quarantined",
                  {"documents": [{k: r[k] for k in ("id", "title", "source", "decision", "quarantined")}
                                 for r in doc_reports]}, ts)
        all_findings += f_ret_all

        # 3. MODEL PLAN + TOOL CALLS -----------------------------------------
        plan = self.llm.plan(message, kept, ctx)
        tool_results, f_tool_all, tool_reports = [], [], []
        for call in plan["calls"]:
            f_t = check_tool_call(call, ctx)
            act_t, pol_t = self.policy.decide(f_t, "tool")
            blocked = self._enforce(mode, act_t)
            result = None if blocked else demo_app.execute_tool(call, ctx)
            tool_results.append({**call, "result": result, "blocked": blocked})
            tool_reports.append({"call": call, "decision": act_t, "blocked": blocked,
                                 "findings": [f.to_dict() for f in f_t], "policies": pol_t})
            self._log(base, "tool", act_t, f_t, pol_t,
                      f"{'BLOCKED ' if blocked else ''}tool call {call['name']}", {"call": call}, ts)
            f_tool_all += f_t
            if act_t == "block":
                self.abuse.violation(user_id)
        if plan["calls"]:
            act_tool = max((r["decision"] for r in tool_reports),
                           key=lambda a: ["allow", "flag", "quarantine", "redact", "block"].index(a))
            stages.append({"stage": "tool", "decision": act_tool, "calls": tool_reports,
                           "findings": [f.to_dict() for f in f_tool_all],
                           "policies": sorted({x for r in tool_reports for x in r["policies"]})})
        all_findings += f_tool_all

        # 4. OUTPUT -----------------------------------------------------------
        output = self.llm.respond(message, kept, plan, tool_results, ctx)
        f_out = detect_leakage(output, demo_app.SYSTEM_PROMPT, demo_app.CANARY) + \
            detect_sensitive(output, "output") + detect_exfiltration(output, "output", p["allowed_output_domains"])
        act_out, pol_out = self.policy.decide(f_out, "output")
        final = output
        if mode == "enforce":
            if act_out == "block":
                final = REFUSAL
            elif act_out == "redact":
                final, _ = redact(output, "medium")
        stages.append({"stage": "output", "decision": act_out, "findings": [f.to_dict() for f in f_out],
                       "policies": pol_out, "raw_output": output if mode == "monitor" else None})
        self._log(base, "output", act_out, f_out, pol_out, f"Model response ({len(output)} chars)",
                  {"response": redact(final)[0]}, ts)
        all_findings += f_out
        if act_out == "block":
            self.abuse.violation(user_id)
        overall = max([s["decision"] for s in stages],
                      key=lambda a: ["allow", "flag", "quarantine", "redact", "block"].index(a))
        return self._finish(base, stages, all_findings, final, overall, t0, ts)

    def _finish(self, base, stages, findings, response, decision, t0, ts):
        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {"trace_id": base["trace_id"], "mode": base["mode"], "user_id": base["user_id"], "role": base["role"],
                "decision": decision, "risk": risk_score(findings), "response": response, "stages": stages,
                "finding_count": len(findings), "latency_ms": latency}

    # ------------------------------------------------------------------ generic evaluation API
    def evaluate(self, body: dict) -> dict:
        """Evaluate an interaction from ANY LLM app (bring-your-own model).

        body: {prompt?, output?, system_prompt?, canary?, documents?: [...], tool_calls?: [...],
               user_id?, role?, app?, session_id?}
        """
        mode = body.get("mode") or self.policy.mode
        p = self.policy.policy
        base = {"trace_id": "tr-" + uuid.uuid4().hex[:10], "session_id": body.get("session_id", "api"),
                "user_id": body.get("user_id", "anonymous"), "role": body.get("role", "customer"),
                "app": body.get("app", "external-app"), "mode": mode, "source": "api"}
        ctx = {"user_id": base["user_id"], "role": base["role"], "approved": body.get("approved", False),
               "tainted": False, "tainted_by": []}
        result = {"trace_id": base["trace_id"], "mode": mode, "stages": {}}
        everything = []

        def run(stage, findings, summary, payload):
            act, pols = self.policy.decide(findings, stage)
            self._log(base, stage, act, findings, pols, summary, payload)
            result["stages"][stage] = {"decision": act, "policies": pols, "findings": [f.to_dict() for f in findings]}
            everything.extend(findings)
            return act

        if body.get("prompt") is not None:
            pr = body["prompt"]
            f = self.abuse.check(base["user_id"], pr, p) + detect_injection(pr, "input") + detect_sensitive(pr, "input")
            if any(x.category == "injection" for x in f):
                ctx["tainted"], ctx["tainted_by"] = True, ["user_prompt"]
            run("input", f, f"[API] prompt ({len(pr)} chars)", {"prompt": redact(pr)[0]})
        if body.get("documents"):
            f = []
            for d in body["documents"]:
                fd = check_document(d, ctx)
                if any(x.category == "injection" for x in fd):
                    ctx["tainted"] = True
                    ctx["tainted_by"].append(d.get("id"))
                f += fd
            run("retrieval", f, f"[API] {len(body['documents'])} documents",
                {"documents": [{"id": d.get("id"), "source": d.get("source")} for d in body["documents"]]})
        if body.get("tool_calls"):
            f = []
            for c in body["tool_calls"]:
                f += check_tool_call(c, ctx)
            run("tool", f, f"[API] {len(body['tool_calls'])} tool calls", {"calls": body["tool_calls"]})
        if body.get("output") is not None:
            out = body["output"]
            f = detect_leakage(out, body.get("system_prompt", ""), body.get("canary", "")) + \
                detect_sensitive(out, "output") + detect_exfiltration(out, "output", p["allowed_output_domains"])
            act = run("output", f, f"[API] output ({len(out)} chars)", {"response": redact(out)[0]})
            if act == "redact":
                result["redacted_output"] = redact(out, "medium")[0]
        decisions = [s["decision"] for s in result["stages"].values()] or ["allow"]
        result["decision"] = max(decisions, key=lambda a: ["allow", "flag", "quarantine", "redact", "block"].index(a))
        result["risk"] = risk_score(everything)
        result["allowed"] = not (mode == "enforce" and result["decision"] == "block")
        return result
