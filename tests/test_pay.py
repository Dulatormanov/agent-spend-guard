"""Guard.pay() blocks what it should, every time. No model calls: the mock API runs in-process."""

import json
import time

import pytest

from tests.conftest import ORG


def test_pays_once_on_a_matching_allow(sandbox):
    decision, payment = sandbox.ask(120)
    assert sandbox.guard.pay(decision, payment).paid
    replay = sandbox.guard.pay(decision, payment)
    assert not replay.paid and "step 12" in replay.message
    lines = [json.loads(line) for line in sandbox.guard.log_path.read_text().splitlines()]
    assert [line["paid"] for line in lines] == [True, False]


def test_no_verdict_no_payment(sandbox):
    payment = {"amount": 120, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"}
    assert not sandbox.guard.pay(None, payment).paid


@pytest.mark.parametrize("change, step", [({"amount": 180}, "step 9"), ({"amount": 119.99}, "step 9"),
                                          ({"currency": "EUR"}, "step 10"), ({"category": "data"}, "step 11")])
def test_payment_must_match_the_allow(sandbox, change, step):
    decision, payment = sandbox.ask(120)
    out = sandbox.guard.pay(decision, {**payment, **change})
    assert not out.paid and step in out.message


def test_recipient_not_on_allowlist(sandbox):
    decision, payment = sandbox.ask(120, recipient="vendor:unknown")
    assert decision["verdict"] == "allow" and "allowlist" in sandbox.guard.pay(decision, payment).message


def test_denial_memory_stops_a_split(sandbox):
    assert sandbox.ask(720)[0]["verdict"] == "deny_limit"
    decision, payment = sandbox.ask(240)
    assert decision["verdict"] == "allow"  # Saifuro allows the piece...
    out = sandbox.guard.pay(decision, payment)
    assert not out.paid and "held for a human" in out.message  # ...the guard doesn't


def test_a_review_pays_only_once_a_person_approves(sandbox):
    decision, payment = sandbox.ask(300)
    assert decision["verdict"] == "review" and "step 8" in sandbox.guard.pay(decision, payment).message
    approval = sandbox.org.post(f"/v1/reviews/{decision['review']['review']}/approve", headers=ORG).json()
    assert sandbox.guard.pay(approval, payment).paid  # a person approved it: the superseding allow pays


def test_expired_allow(sandbox):
    decision, payment = sandbox.ask(120)
    sandbox.guard.clock = lambda: time.time() + 300 + 60  # exp + skew
    assert "step 7" in sandbox.guard.pay(decision, payment).message


def test_mandate_not_agreed_and_sandbox_key(sandbox):
    guard = sandbox.guard
    decision, payment = sandbox.ask(120)
    guard.agreed_mandates = {"mnd_other"}
    assert "step 8" in guard.pay(decision, payment).message
    guard.agreed_mandates, guard.testing_only = {decision["mandate"]}, False  # a production guard
    assert "step 3" in guard.pay(decision, payment).message


def test_observe_mode_pays_and_says_what_it_would_have_blocked(sandbox):
    sandbox.org.post("/v1/enforcement", headers=ORG, json={"mode": "observe"})
    try:
        decision, payment = sandbox.ask(720)
    finally:
        sandbox.org.post("/v1/enforcement", headers=ORG, json={"mode": "enforce"})
    out = sandbox.guard.pay(decision, payment)
    assert out.paid and "would have blocked" in out.message


def test_unknown_kid_refetches_at_most_once_a_minute(sandbox):
    guard, fetches = sandbox.guard, []
    guard.fetch_keys = lambda: (fetches.append(1), setattr(guard, "fetched_at", guard.clock()))
    guard.keys = {"keys": []}  # a cached set that doesn't know the mock's key
    guard.fetched_at = guard.clock()
    decision, payment = sandbox.ask(120)
    for _ in range(3):
        assert "step 4" in guard.pay(decision, payment).message
    assert fetches == []  # fetched less than a minute ago: no refetch yet
    guard.fetched_at -= 61
    guard.pay(decision, payment)
    assert fetches == [1]
