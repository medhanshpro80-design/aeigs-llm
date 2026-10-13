"""Seed the audit log with ~24h of realistic mixed traffic so the dashboard has history."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from aegis import redteam

BENIGN = [b["prompt"] for b in redteam.BENIGN] + [
    "Can I change my delivery address?", "Is express delivery available in Pune?",
    "My headphones arrived, how do I register the warranty?", "Track my order status please",
    "How many days do refunds take?", "What payment methods do you accept?",
]
ATTACKS = [c for c in redteam.CASES if c["id"] != "RT-28"]
USERS = [("C-1001", "customer"), ("C-1002", "customer"), ("C-1003", "customer"), ("AGENT-7", "agent")]
ATTACKER = ("C-1002", "customer")  # one customer turns adversarial in the afternoon


def seed_history(gateway, n: int = 160, hours: int = 24, rng_seed: int = 7):
    rng = random.Random(rng_seed)
    now = datetime.now(timezone.utc)
    stamps = sorted(now - timedelta(seconds=rng.randint(60, hours * 3600)) for _ in range(n))
    for i, ts in enumerate(stamps):
        hours_ago = (now - ts).total_seconds() / 3600
        burst = 5 < hours_ago < 7  # simulated attack campaign window
        if rng.random() < (0.55 if burst else 0.12):
            c = rng.choice(ATTACKS)
            uid, role = (ATTACKER if burst else rng.choice(USERS))
            uid, role = c.get("user_id", uid), c.get("role", role)
            msg = c["prompt"]
        else:
            uid, role = rng.choice(USERS)
            msg = rng.choice(BENIGN)
        mode = "monitor" if hours_ago > 20 else "enforce"  # gateway was in monitor-only mode at first
        gateway.abuse.requests.pop(uid, None)
        if not burst:
            gateway.abuse.violations.pop(uid, None)
        gateway.chat(msg, user_id=uid, role=role, mode=mode, session_id=f"s-{uid}-{int(ts.timestamp()) // 1800}",
                     source="gateway", ts=ts.isoformat(timespec="milliseconds"))
    gateway.abuse.reset()


if __name__ == "__main__":
    from server import audit, gateway
    audit.reset()
    seed_history(gateway)
    redteam.run_suite(gateway)
    print("seeded", len(audit.all()), "events; chain:", audit.verify())
