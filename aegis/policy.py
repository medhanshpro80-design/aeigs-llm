"""Declarative security policies: which findings lead to which action at which stage."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from .detectors import SEVERITY_SCORE, Finding

ACTION_RANK = {"allow": 0, "flag": 1, "quarantine": 2, "redact": 3, "block": 4}

DEFAULT_POLICY = {
    "mode": "enforce",                    # enforce | monitor (monitor = log only, never block)
    "allowed_output_domains": ["acme.com"],
    "rate_limit_per_min": 15,
    "max_prompt_chars": 4000,
    "block_user_after_violations": 3,     # within 10 minutes
    "rules": [
        {"id": "P-INJ-BLOCK", "name": "Block high-confidence prompt injection", "category": "injection",
         "stages": ["input"], "min_severity": "high", "action": "block", "enabled": True},
        {"id": "P-INJ-FLAG", "name": "Flag suspicious prompts", "category": "injection",
         "stages": ["input"], "min_severity": "low", "action": "flag", "enabled": True},
        {"id": "P-RAG-QUAR", "name": "Quarantine documents with injected instructions or bad provenance",
         "category": "injection|provenance", "stages": ["retrieval"], "min_severity": "high",
         "action": "quarantine", "enabled": True},
        {"id": "P-RAG-FLAG", "name": "Flag untrusted retrieval sources", "category": "provenance",
         "stages": ["retrieval"], "min_severity": "low", "action": "flag", "enabled": True},
        {"id": "P-TOOL-BLOCK", "name": "Block tool calls violating least privilege", "category": "tool",
         "stages": ["tool"], "min_severity": "high", "action": "block", "enabled": True},
        {"id": "P-TOOL-FLAG", "name": "Flag tool calls needing review", "category": "tool",
         "stages": ["tool"], "min_severity": "low", "action": "flag", "enabled": True},
        {"id": "P-PII-REDACT", "name": "Redact sensitive data in responses", "category": "sensitive_data",
         "stages": ["output"], "min_severity": "medium", "action": "redact", "enabled": True},
        {"id": "P-PII-IN", "name": "Flag sensitive data submitted by users", "category": "sensitive_data",
         "stages": ["input"], "min_severity": "high", "action": "flag", "enabled": True},
        {"id": "P-EXF-BLOCK", "name": "Block exfiltration channels in output", "category": "exfiltration",
         "stages": ["output"], "min_severity": "high", "action": "block", "enabled": True},
        {"id": "P-EXF-FLAG", "name": "Flag external links in output", "category": "exfiltration",
         "stages": ["output"], "min_severity": "low", "action": "flag", "enabled": True},
        {"id": "P-LEAK-BLOCK", "name": "Block system prompt leakage", "category": "leakage",
         "stages": ["output"], "min_severity": "medium", "action": "block", "enabled": True},
        {"id": "P-ABUSE", "name": "Throttle model abuse / unbounded consumption", "category": "abuse",
         "stages": ["input"], "min_severity": "high", "action": "block", "enabled": True},
    ],
}

POLICY_FILE = Path(__file__).resolve().parent.parent / "policy.json"


class PolicyStore:
    def __init__(self):
        self.policy = copy.deepcopy(DEFAULT_POLICY)
        if POLICY_FILE.exists():
            try:
                self.policy.update(json.loads(POLICY_FILE.read_text()))
            except Exception:
                pass

    def save(self, new: dict):
        self.policy.update(new)
        POLICY_FILE.write_text(json.dumps(self.policy, indent=2))

    def reset(self):
        self.policy = copy.deepcopy(DEFAULT_POLICY)
        POLICY_FILE.unlink(missing_ok=True)

    @property
    def mode(self) -> str:
        return self.policy["mode"]

    def decide(self, findings: list[Finding], stage: str) -> tuple[str, list[str]]:
        """Return (action, matched policy ids) for findings at a given stage."""
        action, matched = "allow", []
        for f in findings:
            for r in self.policy["rules"]:
                if not r["enabled"] or stage not in r["stages"]:
                    continue
                if f.category not in r["category"].split("|"):
                    continue
                if SEVERITY_SCORE[f.severity] < SEVERITY_SCORE[r["min_severity"]]:
                    continue
                f.meta["policy"] = r["id"]
                f.meta["action"] = r["action"]
                if r["id"] not in matched:
                    matched.append(r["id"])
                if ACTION_RANK[r["action"]] > ACTION_RANK[action]:
                    action = r["action"]
                break  # first matching rule per finding (rules are ordered)
        return action, matched


def risk_score(findings: list[Finding]) -> int:
    if not findings:
        return 0
    top = max(SEVERITY_SCORE[f.severity] for f in findings)
    extra = sum(SEVERITY_SCORE[f.severity] for f in findings) - top
    return min(100, top + extra // 5)
