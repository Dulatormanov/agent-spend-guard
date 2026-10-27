"""Ask Saifuro before paying. Fails closed: no verdict means no payment.

Swapping to a real sandbox is three environment variables: SAIFURO_BASE_URL,
SAIFURO_AGENT_KEY, and SAIFURO_ISSUER (whose /.well-known/jwks.json is the key set).
"""

import hashlib
import os
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

import httpx

TOKEN_LIFETIME = 300


@dataclass
class Outcome:
    decision: dict | None  # None means no verdict: do not pay
    message: str  # the code and reason in plain words, for the agent


# Every verdict seen per recipient, oldest first. pay() reads it for denial memory.
# ponytail: in-process; a shared store once the guard runs in more than one process
verdicts_by_recipient: dict[str, list[str]] = {}


def make_client(timeout: float = 10.0) -> httpx.Client:
    return httpx.Client(
        base_url=os.environ.get("SAIFURO_BASE_URL", "http://127.0.0.1:8402/v1"),
        headers={"Authorization": f"Bearer {os.environ['SAIFURO_AGENT_KEY']}"},
        timeout=timeout,
    )


def idempotency_key(task_id: str, amount: float, currency: str, recipient: str, category: str) -> str:
    """Same payment, same key, so a retry after a timeout can't create a second decision."""
    amount = f"{Decimal(str(amount)).normalize():f}"  # 120 and 120.00 are one payment
    return hashlib.sha256("\0".join([task_id, recipient, amount, currency, category]).encode()).hexdigest()


def no_verdict(why: str) -> Outcome:
    return Outcome(None, f"no_verdict: {why}. No payment can be made without a verdict.")


def request_authorization(client: httpx.Client, *, task_id: str, amount: float, currency: str,
                          recipient: str, category: str) -> Outcome:
    body = {"amount": amount, "currency": currency, "recipient": recipient, "category": category}
    key = idempotency_key(task_id, amount, currency, recipient, category)
    for _ in range(3):
        try:
            r = client.post("/authorizations", json=body, headers={"Idempotency-Key": key})
        except httpx.HTTPError as e:  # timeout, connection error
            return no_verdict(f"Saifuro did not answer ({type(e).__name__})")
        if r.status_code != 201:
            return no_verdict(f"Saifuro returned HTTP {r.status_code}")
        try:
            d = r.json()
            verdict, reason = d["verdict"], d["reason"]
            issued = datetime.fromisoformat(d["issued_at"]).timestamp()
        except (ValueError, KeyError, TypeError):
            return no_verdict("Saifuro returned a decision this guard can't read")
        if r.headers.get("Idempotency-Replayed") == "true" and issued + TOKEN_LIFETIME <= time.time():
            # The replayed decision's token has expired: ask again under a key derived from it,
            # so a retry of this retry still replays instead of creating a third decision.
            key = hashlib.sha256((key + d["decision"]).encode()).hexdigest()
            continue
        verdicts_by_recipient.setdefault(recipient, []).append(verdict)
        return Outcome(d, f"{verdict}: {reason}")
    return no_verdict("Saifuro kept replaying expired decisions")
