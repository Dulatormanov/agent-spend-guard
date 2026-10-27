"""request_authorization() fails closed and makes retries safe. No model calls."""

import httpx
import pytest
from fastapi.testclient import TestClient

from guard.client import idempotency_key, request_authorization
from mock_api import app as mock

PAYMENT = {"task_id": "t1", "amount": 120, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"}


def client_returning(handler) -> httpx.Client:
    return httpx.Client(base_url="http://saifuro.test/v1", transport=httpx.MockTransport(handler))


def raise_(e):
    raise e


@pytest.mark.parametrize("handler", [
    lambda req: raise_(httpx.ReadTimeout("slow", request=req)),
    lambda req: raise_(httpx.ConnectError("down", request=req)),
    lambda req: httpx.Response(503, json={"error": {"code": "server_error"}}),
    lambda req: httpx.Response(429, json={"error": {"code": "rate_limited"}}),
    lambda req: httpx.Response(201, text="not json"),
], ids=["timeout", "connection-error", "5xx", "429", "garbage"])
def test_no_verdict_means_no_decision(handler):
    out = request_authorization(client_returning(handler), **PAYMENT)
    assert out.decision is None and out.message.startswith("no_verdict:")


def test_key_is_derived_from_the_payment():
    assert idempotency_key("t1", 120, "USD", "v", "saas") == idempotency_key("t1", 120.00, "USD", "v", "saas")
    assert idempotency_key("t1", 120, "USD", "v", "saas") != idempotency_key("t1", 121, "USD", "v", "saas")
    assert idempotency_key("t1", 120, "USD", "v", "saas") != idempotency_key("t2", 120, "USD", "v", "saas")


def test_expired_replay_retries_with_a_new_key():
    seen_keys = []

    def handler(req):
        seen_keys.append(req.headers["Idempotency-Key"])
        if len(seen_keys) == 1:  # a decision from long ago, replayed
            return httpx.Response(201, headers={"Idempotency-Replayed": "true"}, json={
                "decision": "dec_old", "verdict": "allow", "reason": "within mandate", "issued_at": "2026-01-01T00:00:00Z"})
        return httpx.Response(201, json={"decision": "dec_new", "verdict": "allow", "reason": "within mandate",
                                         "issued_at": "2099-01-01T00:00:00Z"})

    out = request_authorization(client_returning(handler), **PAYMENT)
    assert out.decision["decision"] == "dec_new" and len(set(seen_keys)) == 2


def test_against_the_mock():
    api = TestClient(mock.app, base_url="http://mock")
    org = {"Authorization": f"Bearer {mock.ORG_KEY}"}
    a = api.post("/v1/agents", headers=org, json={"name": "client_test"}).json()
    api.post("/v1/mandates", headers=org, json={
        "principal": "role:procurement_lead", "agent": a["agent"], "categories": ["saas"], "review_above": 250,
        "limits": {"per_transaction": 500, "currency": "USD"}, "expires": "2099-01-01"})
    api.headers["Authorization"] = f"Bearer {a['agent_key']}"
    api.base_url = "http://mock/v1"

    first = request_authorization(api, **PAYMENT)
    assert first.message == "allow: within mandate " + first.decision["mandate"]
    assert request_authorization(api, **PAYMENT).decision == first.decision  # same payment, replayed
    denied = request_authorization(api, **{**PAYMENT, "amount": 720})
    assert denied.message == "deny_limit: amount 720.00 exceeds per_transaction limit 500.00"
