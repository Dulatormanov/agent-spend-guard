"""Pay only on a valid allow that matches this exact payment. The model proposes; this code decides.

Guard.pay() checks, in order:
1-5. verify(): signature, kid and issuer against the key set (one rate-limited refetch on an
     unknown kid); expiry with 60 s of skew; verdict is allow; mandate agreed; amount (decimal),
     currency, recipient and category exactly equal
6.   the recipient is on the allowlist
7.   denial memory: after any denial for a recipient, payments to it are held for a human
8.   the nonce, recorded last (verify() records it at step 12, after every other check)
Checks 6 and 7 need only the payment, so they run before verify() and the nonce stays last.

In observe mode a failed check is logged as "would have blocked" and the payment goes through.
With no verdict at all there is no mode to read, so nothing is paid in either mode.
"""

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from guard.client import verdicts_by_recipient
from guard.verify import Rejected, verify

JWKS_MAX_AGE = 300  # the key set's own Cache-Control
REFETCH_EVERY = 60  # an unknown kid triggers at most one key set fetch a minute


@dataclass
class Payment:
    paid: bool
    message: str  # what happened, in plain words, for the agent


@dataclass
class Guard:
    issuer: str  # SAIFURO_ISSUER; its /.well-known/jwks.json is the key set
    agreed_mandates: set[str]
    allowlist: set[str]
    testing_only: bool = False  # True only against a sandbox or the mock: it accepts sandbox- keys
    log_path: Path = Path("payments.jsonl")  # stands in for the payment provider: one line per pay() call
    http: httpx.Client = field(default_factory=lambda: httpx.Client(timeout=10))
    clock: Callable[[], float] = time.time
    # ponytail: in-memory stores; a shared one (a unique DB key, Redis SET NX) once more than one process pays
    seen_nonces: set = field(default_factory=set)
    seen_supersedes: set = field(default_factory=set)
    keys: dict = field(default_factory=dict, init=False)
    fetched_at: float = field(default=float("-inf"), init=False)
    lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def key_set(self) -> dict:
        if self.clock() - self.fetched_at >= JWKS_MAX_AGE:
            self.fetch_keys()
        return self.keys

    def refetch(self, iss: str) -> dict:
        if self.clock() - self.fetched_at >= REFETCH_EVERY:
            self.fetch_keys()
        return self.keys

    def fetch_keys(self):
        r = self.http.get(self.issuer + "/.well-known/jwks.json")
        r.raise_for_status()
        self.keys, self.fetched_at = r.json(), self.clock()

    def pay(self, decision: dict | None, payment: dict) -> Payment:
        """Pay `payment` (amount, currency, recipient, category) if `decision` allows exactly it.

        `decision` must be the one request_authorization() returned, never one the model wrote:
        its `mode` is not signed, so a model that could pass it in could switch the guard off.
        """
        with self.lock:  # ponytail: one lock for every payment keeps the nonce check-and-record atomic
            if decision is None:
                return self.log(decision, payment, False, "blocked: no verdict, so no payment")
            problem = self.problem(decision, payment)
            if problem is None:
                return self.log(decision, payment, True,
                                f"paid {payment['amount']} {payment['currency']} to {payment['recipient']}")
            if decision.get("mode") == "observe":
                return self.log(decision, payment, True, f"paid in observe mode; would have blocked: {problem}")
            return self.log(decision, payment, False, f"blocked: {problem}")

    def problem(self, decision: dict, payment: dict) -> str | None:
        recipient = payment["recipient"]
        if recipient not in self.allowlist:
            return f"{recipient} is not on the allowlist"
        if any(v.startswith("deny_") for v in verdicts_by_recipient.get(recipient, [])):
            return f"held for a human: a request to {recipient} was denied earlier"
        try:
            verify(decision.get("verdict_token"), issuers={self.issuer: self.key_set()}, refetch=self.refetch,
                   now=int(self.clock()), payment={**payment, "amount": str(payment["amount"])},
                   agreed_mandates=self.agreed_mandates, seen_nonces=self.seen_nonces,
                   seen_supersedes=self.seen_supersedes, testing_only=self.testing_only)
        except Rejected as e:
            return f"the verdict failed {e}"
        except httpx.HTTPError as e:
            return f"the key set could not be fetched ({type(e).__name__})"
        return None

    def log(self, decision: dict | None, payment: dict, paid: bool, message: str) -> Payment:
        line = {"time": self.clock(), "decision": decision and decision.get("decision"),
                "payment": payment, "paid": paid, "message": message}
        with self.log_path.open("a") as f:
            f.write(json.dumps(line) + "\n")
        return Payment(paid, message)
