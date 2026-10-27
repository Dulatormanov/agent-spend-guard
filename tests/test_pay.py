"""Guard.pay() blocks what it should, every time. No model calls: the mock API runs in-process."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from guard import client
from guard.client import request_authorization
from guard.pay import Guard
from mock_api import app as mock

ORG = {"Authorization": f"Bearer {mock.ORG_KEY}"}
_names = iter(range(10**6))


@pytest.fixture
def setup(tmp_path):
    """A fresh agent with the eval mandate, a guard trusting the mock, and ask() for decisions."""
    client.verdicts_by_recipient.clear()
    org = TestClient(mock.app, base_url="http://mock")
    a = org.post("/v1/agents", headers=ORG, json={"name": f"pay_{next(_names)}"}).json()
    m = org.post("/v1/mandates", headers=ORG, json={
        "principal": "role:procurement_lead", "agent": a["agent"], "categories": ["saas", "data"], "review_above": 250,
        "limits": {"per_transaction": 500, "per_month": 5000, "currency": "USD"}, "expires": "2099-01-01"}).json()
    agent_api = TestClient(mock.app, base_url="http://mock/v1", headers={"Authorization": f"Bearer {a['agent_key']}"})
    guard = Guard(issuer=mock.ISSUER, agreed_mandates={m["mandate"]}, allowlist={"vendor:acme_saas", "vendor:data_co"},
                  testing_only=True, log_path=tmp_path / "payments.jsonl", http=org)

    def ask(amount, recipient="vendor:acme_saas", category="saas"):
        p = {"amount": amount, "currency": "USD", "recipient": recipient, "category": category}
        return request_authorization(agent_api, task_id=f"t{amount}", **p).decision, p

    return guard, ask, org, m["mandate"]


def test_pays_once_on_a_matching_allow(setup):
    guard, ask, *_ = setup
    decision, payment = ask(120)
    assert guard.pay(decision, payment).paid
    replay = guard.pay(decision, payment)
    assert not replay.paid and "step 12" in replay.message
    lines = [json.loads(line) for line in guard.log_path.read_text().splitlines()]
    assert [line["paid"] for line in lines] == [True, False]


def test_no_verdict_no_payment(setup):
    guard, *_ = setup
    assert not guard.pay(None, {"amount": 120, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"}).paid


@pytest.mark.parametrize("change, step", [({"amount": 180}, "step 9"), ({"amount": 119.99}, "step 9"),
                                          ({"currency": "EUR"}, "step 10"), ({"category": "data"}, "step 11")])
def test_payment_must_match_the_allow(setup, change, step):
    guard, ask, *_ = setup
    decision, payment = ask(120)
    out = guard.pay(decision, {**payment, **change})
    assert not out.paid and step in out.message


def test_recipient_not_on_allowlist(setup):
    guard, ask, *_ = setup
    decision, payment = ask(120, recipient="vendor:unknown")
    assert decision["verdict"] == "allow" and "allowlist" in guard.pay(decision, payment).message


def test_denial_memory_stops_a_split(setup):
    guard, ask, *_ = setup
    assert ask(720)[0]["verdict"] == "deny_limit"
    decision, payment = ask(240)
    assert decision["verdict"] == "allow"  # Saifuro allows the piece...
    out = guard.pay(decision, payment)
    assert not out.paid and "held for a human" in out.message  # ...the guard doesn't


def test_a_review_pays_only_once_a_person_approves(setup):
    guard, ask, org, _ = setup
    decision, payment = ask(300)
    assert decision["verdict"] == "review" and "step 8" in guard.pay(decision, payment).message
    approval = org.post(f"/v1/reviews/{decision['review']['review']}/approve", headers=ORG).json()
    assert guard.pay(approval, payment).paid  # a person approved it: the superseding allow pays


def test_expired_allow(setup):
    guard, ask, *_ = setup
    decision, payment = ask(120)
    guard.clock = lambda: time.time() + 300 + 60  # exp + skew
    assert "step 7" in guard.pay(decision, payment).message


def test_mandate_not_agreed_and_sandbox_key(setup):
    guard, ask, *_ = setup
    decision, payment = ask(120)
    guard.agreed_mandates = {"mnd_other"}
    assert "step 8" in guard.pay(decision, payment).message
    guard.agreed_mandates, guard.testing_only = {decision["mandate"]}, False  # a production guard
    assert "step 3" in guard.pay(decision, payment).message


def test_observe_mode_pays_and_says_what_it_would_have_blocked(setup):
    guard, ask, org, _ = setup
    org.post("/v1/enforcement", headers=ORG, json={"mode": "observe"})
    try:
        decision, payment = ask(720)
    finally:
        org.post("/v1/enforcement", headers=ORG, json={"mode": "enforce"})
    out = guard.pay(decision, payment)
    assert out.paid and "would have blocked" in out.message


def test_unknown_kid_refetches_at_most_once_a_minute(setup):
    guard, ask, org, _ = setup
    fetches = []
    guard.fetch_keys = lambda: (fetches.append(1), setattr(guard, "fetched_at", guard.clock()))
    guard.keys = {"keys": []}  # a cached set that doesn't know the mock's key
    guard.fetched_at = guard.clock()
    decision, payment = ask(120)
    for _ in range(3):
        assert "step 4" in guard.pay(decision, payment).message
    assert fetches == []  # fetched less than a minute ago: no refetch yet
    guard.fetched_at -= 61
    guard.pay(decision, payment)
    assert fetches == [1]
