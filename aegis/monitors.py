"""Tool-permission monitoring and retrieval-provenance checks."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .detectors import Finding, detect_injection, find_sensitive

# --------------------------------------------------------------------------- tool registry
# Least-privilege manifest for every tool the agent can call.
TOOL_REGISTRY: dict[str, dict] = {
    "search_kb": {
        "risk": "low", "roles": ["customer", "agent", "admin"], "description": "Search the knowledge base",
    },
    "get_order_status": {
        "risk": "low", "roles": ["customer", "agent", "admin"], "description": "Look up an order",
        "owner_arg": "customer_id",
    },
    "get_customer_record": {
        "risk": "medium", "roles": ["customer", "agent", "admin"], "description": "Read a customer profile (PII)",
        "owner_arg": "customer_id",
    },
    "send_email": {
        "risk": "high", "roles": ["agent", "admin"], "description": "Send an email",
        "allowed_recipient_domains": ["acme.com"], "requires_approval": True,
    },
    "http_fetch": {
        "risk": "medium", "roles": ["agent", "admin"], "description": "Fetch a URL",
        "allowed_domains": ["acme.com", "docs.acme.com", "status.acme.com"],
    },
    "run_sql": {
        "risk": "high", "roles": ["admin"], "description": "Query the analytics DB", "read_only": True,
    },
    "issue_refund": {
        "risk": "high", "roles": ["customer", "agent", "admin"], "description": "Issue a refund", "max_amount": 200,
    },
    "delete_account": {
        "risk": "critical", "roles": ["admin"], "description": "Delete a customer account", "requires_approval": True,
    },
}

WRITE_SQL = re.compile(r"\b(insert|update|delete|drop|alter|truncate|grant|create|replace)\b", re.I)


def check_tool_call(call: dict, ctx: dict) -> list[Finding]:
    """call = {name, args}; ctx = {role, user_id, tainted, tainted_by}"""
    name, args = call.get("name", ""), call.get("args", {}) or {}
    spec = TOOL_REGISTRY.get(name)
    f: list[Finding] = []
    ev = f"{name}({', '.join(f'{k}={v!r}' for k, v in args.items())})"[:160]

    def add(rule, sev, msg, owasp="LLM06", **meta):
        f.append(Finding("tool", rule, sev, msg, "tool", ev, owasp, {"tool": name, **meta}))

    if not spec:
        add("TOOL-001", "high", f"Call to unregistered tool '{name}'")
        return f
    role = ctx.get("role", "customer")
    if role not in spec["roles"]:
        add("TOOL-002", "high", f"Role '{role}' is not permitted to call '{name}' (risk: {spec['risk']})")
    owner_arg = spec.get("owner_arg")
    if owner_arg and role == "customer" and args.get(owner_arg) and args[owner_arg] != ctx.get("user_id"):
        add("TOOL-003", "high", f"Cross-tenant access: {owner_arg}={args[owner_arg]} but session user is {ctx.get('user_id')}",
            "LLM02")
    if name == "send_email":
        to = str(args.get("to", ""))
        dom = to.split("@")[-1].lower()
        if dom not in spec["allowed_recipient_domains"]:
            add("TOOL-004", "critical", f"Email to external domain '{dom}'")
        body = f"{args.get('subject', '')} {args.get('body', '')}"
        if find_sensitive(body):
            add("TOOL-005", "critical", "Tool arguments contain sensitive data (possible exfiltration)", "LLM02")
    if name == "http_fetch":
        host = (urlparse(str(args.get("url", ""))).hostname or "").lower()
        if not any(host == d or host.endswith("." + d) for d in spec["allowed_domains"]):
            add("TOOL-006", "high", f"HTTP fetch to non-allowlisted host '{host}' (SSRF/exfil risk)")
        if find_sensitive(str(args.get("url", ""))):
            add("TOOL-005", "critical", "Sensitive data embedded in outbound URL", "LLM02")
    if name == "run_sql" and WRITE_SQL.search(str(args.get("query", ""))):
        add("TOOL-007", "critical", "Write/DDL statement on read-only SQL tool")
    if name == "issue_refund" and float(args.get("amount", 0) or 0) > spec["max_amount"]:
        add("TOOL-008", "high", f"Refund {args.get('amount')} exceeds limit {spec['max_amount']}")
    if spec.get("requires_approval") and not ctx.get("approved"):
        add("TOOL-009", "medium" if spec["risk"] != "critical" else "high",
            f"'{name}' requires human approval (none recorded)")
    if ctx.get("tainted") and spec["risk"] in ("medium", "high", "critical"):
        add("TOOL-010", "critical",
            f"{spec['risk'].title()}-risk tool call issued after untrusted/injected content entered context",
            "LLM01", tainted_by=ctx.get("tainted_by"))
    return f


# --------------------------------------------------------------------------- retrieval provenance
# Approved-source registry: source -> trust level + classification
SOURCE_REGISTRY: dict[str, dict] = {
    "kb://policies": {"trust": "trusted", "classification": "public", "owner": "support-ops"},
    "kb://product-docs": {"trust": "trusted", "classification": "public", "owner": "product"},
    "kb://internal-runbooks": {"trust": "trusted", "classification": "internal", "owner": "sre"},
    "kb://hr": {"trust": "trusted", "classification": "confidential", "owner": "hr"},
    "web://community-forum": {"trust": "untrusted", "classification": "public", "owner": "external"},
}
CLEARANCE = {"customer": ["public"], "agent": ["public", "internal"], "admin": ["public", "internal", "confidential"]}


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_document(doc: dict, ctx: dict) -> list[Finding]:
    """doc = {id, source, content, sha256 (registered at ingestion), ingested_at}"""
    f: list[Finding] = []
    did = doc.get("id", "?")
    src = doc.get("source", "")
    reg = SOURCE_REGISTRY.get(src)

    def add(rule, sev, msg, owasp="LLM08", ev=""):
        f.append(Finding("provenance", rule, sev, msg, "retrieval", ev or f"{did} @ {src}", owasp,
                         {"doc_id": did, "source": src}))

    if not reg:
        add("PROV-001", "high", f"Document from unregistered source '{src}'", "LLM04")
    elif reg["trust"] == "untrusted":
        add("PROV-002", "medium", f"Document from untrusted source '{src}'", "LLM04")
    if doc.get("sha256") and doc["sha256"] != sha256(doc.get("content", "")):
        add("PROV-003", "critical", "Content hash mismatch: document modified after ingestion (tampering/poisoning)",
            "LLM04")
    if reg:
        allowed = CLEARANCE.get(ctx.get("role", "customer"), ["public"])
        if reg["classification"] not in allowed:
            add("PROV-004", "high",
                f"'{reg['classification']}' document retrieved for role '{ctx.get('role')}' (access-control bypass)",
                "LLM02")
    ts = doc.get("ingested_at")
    if ts:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).days
        if age > 365:
            add("PROV-005", "low", f"Stale document ({age} days old)", "LLM08")
    inj = detect_injection(doc.get("content", ""), stage="retrieval")
    for i in inj:
        i.meta.update({"doc_id": did, "source": src})
    f.extend(inj)
    return f
