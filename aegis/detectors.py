"""Content detectors: prompt injection, sensitive data, exfiltration channels, leakage.

Each detector returns a list of Finding objects. Detectors are pure functions so they
can be reused at every stage of the pipeline (user input, retrieved docs, tool args, output).
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

SEVERITY_SCORE = {"low": 10, "medium": 30, "high": 60, "critical": 90}

# OWASP Top 10 for LLM Applications (2025)
OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM10": "Unbounded Consumption",
}


@dataclass
class Finding:
    category: str          # injection | sensitive_data | exfiltration | leakage | tool | provenance | abuse
    rule: str              # stable rule id, e.g. INJ-001
    severity: str          # low | medium | high | critical
    message: str
    stage: str = ""        # input | retrieval | tool | output
    evidence: str = ""
    owasp: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["owasp_name"] = OWASP.get(self.owasp, "")
        return d


def _snip(text: str, start: int, end: int, pad: int = 30) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return ("…" if s > 0 else "") + text[s:e].replace("\n", " ") + ("…" if e < len(text) else "")


# --------------------------------------------------------------------------- normalisation

ZERO_WIDTH = re.compile(r"[​-‏⁠-⁤﻿­]")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def normalise(text: str) -> str:
    """Collapse common obfuscation tricks so regexes see the attacker's real intent."""
    t = unicodedata.normalize("NFKC", text)
    t = ZERO_WIDTH.sub("", t)
    t = t.lower().translate(LEET)
    t = re.sub(r"[\s_\-\.\*]+", " ", t)
    return t


# --------------------------------------------------------------------------- prompt injection

INJECTION_RULES = [
    ("INJ-001", "high", "Instruction override attempt",
     r"\b(ignore|disregard|forget|override|bypass|skip)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|system|original)\b.{0,30}\b(instructions?|rules?|prompts?|directives?|guidelines?|policies|constraints)\b"),
    ("INJ-002", "high", "System prompt extraction attempt",
     r"\b(reveal|show|print|repeat|output|display|dump|leak|tell me|what (is|are|was))\b.{0,40}\b(system prompt|system message|initial (prompt|instructions)|hidden (prompt|instructions)|your (instructions|prompt|rules))\b"),
    ("INJ-003", "high", "Persona / jailbreak framing",
     r"\b(you are now|from now on you are|act as|pretend (to be|you are)|roleplay as)\b.{0,60}\b(dan|unfiltered|uncensored|jailbroken|evil|no (rules|restrictions|limits)|without (any )?(rules|restrictions|filters))\b"),
    ("INJ-004", "medium", "Known jailbreak keyword",
     r"\b(dan mode|developer mode|jailbreak|do anything now|god mode|sudo mode|admin mode|unrestricted mode)\b"),
    ("INJ-005", "high", "Chat-template / delimiter injection",
     r"(<\|im_start\|>|<\|im_end\|>|\[/?inst\]|<</?sys>>|</?system>|###\s*(system|instruction)|\bend of (system )?prompt\b)"),
    ("INJ-006", "medium", "Injected new-instruction block",
     r"\b(new|updated|real|actual|important) (instructions?|task|directive)s?\s*[:\-]"),
    ("INJ-007", "high", "Instruction to perform hidden action",
     r"\b(do not|don't|never) (tell|inform|mention|reveal to|alert) (the )?(user|human|customer)\b"),
    ("INJ-008", "high", "Instruction to invoke tools / send data",
     r"\b(call|invoke|use|run|execute)\b.{0,20}\b(send email|send_email|http_fetch|run_sql|delete_account|tool|function)\b.{0,80}\b(to|with|containing|including)\b"),
    ("INJ-009", "medium", "Safety-disable request",
     r"\b(disable|turn off|remove|deactivate)\b.{0,20}\b(safety|filters?|guardrails?|moderation|content policy)\b"),
]
_INJ = [(rid, sev, msg, re.compile(p, re.I | re.S)) for rid, sev, msg, p in INJECTION_RULES]
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def detect_injection(text: str, stage: str = "input") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings
    indirect = stage == "retrieval"
    norm = normalise(text)

    for rid, sev, msg, rx in _INJ:
        m = rx.search(text) or rx.search(norm)
        if m:
            src = text if rx.search(text) else norm
            findings.append(Finding(
                "injection", rid, "critical" if indirect and sev == "high" else sev,
                ("Indirect injection in retrieved content: " if indirect else "") + msg,
                stage, _snip(src, m.start(), m.end()), "LLM01",
                {"indirect": indirect}))

    if ZERO_WIDTH.search(text):
        findings.append(Finding("injection", "INJ-010", "medium", "Hidden zero-width characters (obfuscation)",
                                stage, f"{len(ZERO_WIDTH.findall(text))} invisible chars", "LLM01"))

    # Encoded payloads: decode base64 blobs and re-scan
    for m in B64_BLOB.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4)).decode("utf-8")
        except Exception:
            continue
        if decoded.isprintable() and any(rx.search(decoded) for _, _, _, rx in _INJ):
            findings.append(Finding("injection", "INJ-011", "high", "Base64-encoded injection payload",
                                    stage, f"decoded: {decoded[:80]}", "LLM01"))
            break

    # Hidden text in markup (HTML comments / white-on-white) is a classic indirect vector
    if indirect and re.search(r"<!--.*?(instruction|assistant|ai|ignore).*?-->", text, re.I | re.S):
        findings.append(Finding("injection", "INJ-012", "high", "Instructions hidden in HTML comment",
                                stage, "", "LLM01", {"indirect": True}))
    return findings


def injection_score(findings: list[Finding]) -> float:
    s = sum(SEVERITY_SCORE[f.severity] for f in findings if f.category == "injection")
    return min(1.0, s / 100)


# --------------------------------------------------------------------------- sensitive data

def _luhn(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return total % 10 == 0


# (rule, type, severity, regex, validator)
SENSITIVE_RULES = [
    ("PII-001", "email", "low", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", None),
    ("PII-002", "phone", "low", r"(?<!\d)(\+?\d{1,3}[\s-]?)?\(?\d{3,5}\)?[\s-]?\d{3,4}[\s-]?\d{4}(?!\d)", None),
    ("PII-003", "credit_card", "high", r"\b(?:\d[ -]?){13,19}\b", _luhn),
    ("PII-004", "us_ssn", "high", r"\b\d{3}-\d{2}-\d{4}\b", None),
    ("PII-005", "aadhaar", "high", r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b", None),
    ("PII-006", "pan", "medium", r"\b[A-Z]{5}\d{4}[A-Z]\b", None),
    ("SEC-001", "aws_access_key", "critical", r"\bAKIA[0-9A-Z]{16}\b", None),
    ("SEC-002", "api_key", "critical", r"\b(sk-[A-Za-z0-9_\-]{20,}|sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{30,}|xox[bp]-[A-Za-z0-9-]{20,})\b", None),
    ("SEC-003", "private_key", "critical", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", None),
    ("SEC-004", "jwt", "high", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", None),
    ("SEC-005", "password", "high", r"\b(password|passwd|pwd|secret)\s*[:=]\s*\S{4,}", None),
    ("SEC-006", "db_connection_string", "critical", r"\b(postgres|mysql|mongodb(\+srv)?|redis)://[^\s:]+:[^\s@]+@\S+", None),
]
_SENS = [(rid, typ, sev, re.compile(p, re.I if rid.startswith("SEC-005") else 0), v) for rid, typ, sev, p, v in SENSITIVE_RULES]


def find_sensitive(text: str) -> list[tuple[str, str, str, re.Match]]:
    out = []
    taken: list[tuple[int, int]] = []
    # Highest severity first so a card number isn't also reported as a phone number
    for rid, typ, sev, rx, validator in sorted(_SENS, key=lambda r: -SEVERITY_SCORE[r[2]]):
        for m in rx.finditer(text or ""):
            if validator and not validator(m.group(0)):
                continue
            if any(m.start() < e and s < m.end() for s, e in taken):
                continue
            taken.append((m.start(), m.end()))
            out.append((rid, typ, sev, m))
    return out


def mask(value: str) -> str:
    v = value.strip()
    return v[:2] + "*" * max(0, len(v) - 4) + v[-2:] if len(v) > 4 else "****"


def detect_sensitive(text: str, stage: str) -> list[Finding]:
    findings = []
    for rid, typ, sev, m in find_sensitive(text):
        owasp = "LLM02"
        findings.append(Finding("sensitive_data", rid, sev, f"Sensitive data detected: {typ}", stage,
                                mask(m.group(0)), owasp, {"type": typ}))
    return findings


def redact(text: str, min_severity: str = "low") -> tuple[str, int]:
    floor = SEVERITY_SCORE[min_severity]
    hits = sorted((h for h in find_sensitive(text) if SEVERITY_SCORE[h[2]] >= floor),
                  key=lambda h: h[3].start(), reverse=True)
    for _, typ, _, m in hits:
        text = text[:m.start()] + f"[REDACTED:{typ}]" + text[m.end():]
    return text, len(hits)


# --------------------------------------------------------------------------- exfiltration channels

URL_RX = re.compile(r"https?://[^\s)\]\"'>]+", re.I)
MD_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)", re.I)


def detect_exfiltration(text: str, stage: str, allowed_domains: list[str]) -> list[Finding]:
    findings = []
    if not text:
        return findings

    def allowed(url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in allowed_domains)

    for m in MD_IMAGE.finditer(text):
        url = m.group(1)
        if not allowed(url):
            sev = "critical" if urlparse(url).query else "high"
            findings.append(Finding("exfiltration", "EXF-001", sev,
                                    "Markdown image to external host (zero-click exfiltration channel)",
                                    stage, url[:120], "LLM05", {"host": urlparse(url).hostname}))
    img_urls = {m.group(1) for m in MD_IMAGE.finditer(text)}
    for m in URL_RX.finditer(text):
        url = m.group(0)
        if url in img_urls or allowed(url):
            continue
        q = urlparse(url).query
        if q and (len(q) > 40 or find_sensitive(q) or B64_BLOB.search(q)):
            findings.append(Finding("exfiltration", "EXF-002", "high",
                                    "External URL carrying encoded/sensitive data in query string",
                                    stage, url[:120], "LLM05", {"host": urlparse(url).hostname}))
        else:
            findings.append(Finding("exfiltration", "EXF-003", "low", "Link to non-allowlisted domain",
                                    stage, url[:120], "LLM05", {"host": urlparse(url).hostname}))
    if re.search(r"<script\b|javascript:|onerror\s*=", text, re.I):
        findings.append(Finding("exfiltration", "EXF-004", "high", "Active content (script/XSS) in model output",
                                stage, "", "LLM05"))
    return findings


# --------------------------------------------------------------------------- system prompt leakage

def detect_leakage(output: str, system_prompt: str, canary: str) -> list[Finding]:
    findings = []
    if not output:
        return findings
    if canary and canary in output:
        findings.append(Finding("leakage", "LEAK-001", "critical", "Canary token from system prompt found in output",
                                "output", canary, "LLM07"))
    # n-gram overlap with the system prompt
    def grams(t: str, n: int = 6) -> set:
        w = re.findall(r"\w+", t.lower())
        return {" ".join(w[i:i + n]) for i in range(len(w) - n + 1)}
    sp, out = grams(system_prompt), grams(output)
    if sp:
        overlap = len(sp & out) / len(sp)
        if overlap > 0.15:
            findings.append(Finding("leakage", "LEAK-002", "high" if overlap > 0.35 else "medium",
                                    f"Output reproduces {overlap:.0%} of the system prompt",
                                    "output", "", "LLM07", {"overlap": round(overlap, 2)}))
    return findings
