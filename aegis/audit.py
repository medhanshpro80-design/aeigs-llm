"""Tamper-evident audit log (SQLite, SHA-256 hash chain).

Every event stores the hash of the previous event; editing or deleting any row breaks
the chain, which /api/audit/verify detects.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "aegis.db"
GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT, ts TEXT, trace_id TEXT, session_id TEXT, user_id TEXT, role TEXT, app TEXT,
  stage TEXT, decision TEXT, risk INTEGER, mode TEXT, summary TEXT,
  findings TEXT, policies TEXT, payload TEXT, source TEXT,
  prev_hash TEXT, hash TEXT
);
CREATE INDEX IF NOT EXISTS ix_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_trace ON events(trace_id);
CREATE TABLE IF NOT EXISTS redteam_runs (
  id TEXT PRIMARY KEY, ts TEXT, mode TEXT, summary TEXT, results TEXT
);
"""

HASHED_FIELDS = ["id", "ts", "trace_id", "session_id", "user_id", "role", "app", "stage", "decision",
                 "risk", "mode", "summary", "findings", "policies", "payload", "source", "prev_hash"]


def _digest(row: dict) -> str:
    canon = json.dumps({k: row[k] for k in HASHED_FIELDS}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path = DB_PATH):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def _last_hash(self) -> str:
        r = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        return r["hash"] if r else GENESIS

    def log(self, *, trace_id, session_id, user_id, role, app, stage, decision, risk, mode, summary,
            findings, policies, payload, source="gateway", ts: str | None = None) -> dict:
        with self.lock:
            row = {
                "id": uuid.uuid4().hex[:12],
                "ts": ts or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "trace_id": trace_id, "session_id": session_id, "user_id": user_id, "role": role,
                "app": app, "stage": stage, "decision": decision, "risk": int(risk), "mode": mode,
                "summary": summary,
                "findings": json.dumps(findings), "policies": json.dumps(policies),
                "payload": json.dumps(payload), "source": source,
                "prev_hash": self._last_hash(),
            }
            row["hash"] = _digest(row)
            cols = ",".join(row)
            self.db.execute(f"INSERT INTO events ({cols}) VALUES ({','.join('?' * len(row))})", list(row.values()))
            self.db.commit()
            return row

    @staticmethod
    def _decode(r: sqlite3.Row) -> dict:
        d = dict(r)
        for k in ("findings", "policies", "payload"):
            d[k] = json.loads(d[k]) if d[k] else None
        return d

    def query(self, limit=200, decision=None, stage=None, category=None, user_id=None, trace_id=None,
              since=None, q=None) -> list[dict]:
        sql, args = "SELECT * FROM events WHERE 1=1", []
        if decision:
            sql += " AND decision=?"; args.append(decision)
        if stage:
            sql += " AND stage=?"; args.append(stage)
        if user_id:
            sql += " AND user_id=?"; args.append(user_id)
        if trace_id:
            sql += " AND trace_id=?"; args.append(trace_id)
        if since:
            sql += " AND ts>=?"; args.append(since)
        if category:
            sql += " AND findings LIKE ?"; args.append(f'%"category": "{category}"%')
        if q:
            sql += " AND (summary LIKE ? OR payload LIKE ? OR findings LIKE ?)"; args += [f"%{q}%"] * 3
        sql += " ORDER BY seq DESC LIMIT ?"; args.append(limit)
        with self.lock:
            return [self._decode(r) for r in self.db.execute(sql, args).fetchall()]

    def all(self) -> list[dict]:
        with self.lock:
            return [self._decode(r) for r in self.db.execute("SELECT * FROM events ORDER BY seq").fetchall()]

    def verify(self) -> dict:
        with self.lock:
            rows = [dict(r) for r in self.db.execute("SELECT * FROM events ORDER BY seq").fetchall()]
        prev = GENESIS
        for r in rows:
            if r["prev_hash"] != prev or _digest(r) != r["hash"]:
                return {"valid": False, "events": len(rows), "broken_at": r["seq"], "event_id": r["id"],
                        "reason": "prev_hash link broken" if r["prev_hash"] != prev else "row content altered"}
            prev = r["hash"]
        return {"valid": True, "events": len(rows), "head": prev}

    def tamper_demo(self) -> dict:
        """Simulate an insider editing a logged decision (for the demo)."""
        with self.lock:
            r = self.db.execute("SELECT seq FROM events WHERE decision='block' ORDER BY seq DESC LIMIT 1").fetchone() \
                or self.db.execute("SELECT seq FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            if not r:
                return {"tampered": None}
            self.db.execute("UPDATE events SET decision='allow', risk=0 WHERE seq=?", (r["seq"],))
            self.db.commit()
            return {"tampered": r["seq"]}

    def save_run(self, run: dict):
        with self.lock:
            self.db.execute("INSERT INTO redteam_runs VALUES (?,?,?,?,?)",
                            (run["id"], run["ts"], run["mode"], json.dumps(run["summary"]), json.dumps(run["results"])))
            self.db.commit()

    def runs(self, limit=10) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM redteam_runs ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r["id"], "ts": r["ts"], "mode": r["mode"], "summary": json.loads(r["summary"]),
                 "results": json.loads(r["results"])} for r in rows]

    def reset(self):
        with self.lock:
            self.db.executescript("DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS redteam_runs;" + SCHEMA)
