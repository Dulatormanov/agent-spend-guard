"""The mock behaves as docs.saifuro.com describes. No model calls."""

import jwt
import pytest
from fastapi.testclient import TestClient

from mock_api import app as mock

ORG = {"Authorization": f"Bearer {mock.ORG_KEY}"}
MANDATE = {"principal": "role:procurement_lead", "limits": {"per_transaction": 500, "per_month": 5000, "currency": "USD"},
           "categories": ["saas", "data"], "review_above": 250, "expires": "2099-01-01"}
_names = iter(range(10**6))


@pytest.fixture
def api():
    return TestClient(mock.app)


@pytest.fixture
def agent(api):
    """A fresh agent holding the eval mandate; returns (agent headers, agent id, mandate id)."""
    a = api.post("/v1/agents", headers=ORG, json={"name": f"test_{next(_names)}"}).json()
    m = api.post("/v1/mandates", headers=ORG, json={**MANDATE, "agent": a["agent"]}).json()
    return {"Authorization": f"Bearer {a['agent_key']}"}, a["agent"], m["mandate"]


def ask(api, headers, amount, category="saas", recipient="vendor:acme_saas", **extra):
    r = api.post("/v1/authorizations", headers={**headers, **extra},
                 json={"amount": amount, "currency": "USD", "recipient": recipient, "category": category})
    assert r.status_code == 201, r.text  # a denial is a 201, not an error
    return r


def claims(api, token):
    key = jwt.PyJWKSet.from_dict(api.get("/.well-known/jwks.json").json())[jwt.get_unverified_header(token)["kid"]]
    return jwt.decode(token, key.key, algorithms=["ES256"])


def test_deny_limit_is_signed_and_expires(api, agent):
    headers, agent_id, mandate_id = agent
    d = ask(api, headers, 720.00).json()
    assert (d["verdict"], d["reason"]) == ("deny_limit", "amount 720.00 exceeds per_transaction limit 500.00")
    assert d["mode"] == "enforce" and "expires_at" not in d  # expires_at is on allow only
    c = claims(api, d["verdict_token"])
    assert jwt.get_unverified_header(d["verdict_token"])["kid"].startswith("sandbox-")
    assert c["exp"] == c["iat"] + 300 and c["jti"] == d["decision"] and c["mandate"] == mandate_id
    assert c["request"] == {"agent": agent_id, "amount": 720, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"}
    assert not {"reason", "mode", "metadata"} & c.keys()


def test_check_order(api, agent):
    headers, agent_id, mandate_id = agent
    assert ask(api, headers, 120).json()["verdict"] == "allow"
    assert ask(api, headers, 300).json()["verdict"] == "review"
    assert ask(api, headers, 720, category="consulting").json()["verdict"] == "deny_category"  # category before limit
    api.post(f"/v1/mandates/{mandate_id}/revoke", headers=ORG)
    assert ask(api, headers, 720, category="consulting").json()["verdict"] == "deny_revoked"  # revoked before both


def test_no_mandate_in_currency_and_expired(api, agent):
    headers, agent_id, _ = agent
    r = api.post("/v1/authorizations", headers=headers,
                 json={"amount": 10, "currency": "EUR", "recipient": "vendor:x", "category": "saas"}).json()
    assert r["verdict"] == "deny_no_mandate" and "mandate" not in r and "mandate" not in claims(api, r["verdict_token"])
    old = {**MANDATE, "agent": agent_id, "limits": {**MANDATE["limits"], "currency": "GBP"}, "expires": "2020-01-01"}
    assert api.post("/v1/mandates", headers=ORG, json=old).json()["status"] == "expired"
    r = api.post("/v1/authorizations", headers=headers,
                 json={"amount": 10, "currency": "GBP", "recipient": "vendor:x", "category": "saas"}).json()
    assert r["verdict"] == "deny_expired"


def test_split_payment_gets_three_allows(api, agent):
    """The gap the guard's denial memory exists for: $720 is denied, 3 x $240 each pass."""
    headers, *_ = agent
    assert ask(api, headers, 720).json()["verdict"] == "deny_limit"
    assert [ask(api, headers, 240).json()["verdict"] for _ in range(3)] == ["allow"] * 3


def test_velocity(api, agent):
    headers, *_ = agent
    verdicts = [ask(api, headers, 5).json()["verdict"] for _ in range(11)]
    assert verdicts == ["allow"] * 10 + ["deny_velocity"]


def test_review_approval(api, agent):
    headers, *_ = agent
    d = ask(api, headers, 300).json()
    review = d["review"]
    assert review["waits_for"] == "role:procurement_lead" and review["status"] == "pending"
    assert api.post(f"/v1/reviews/{review['review']}/approve", headers=headers).status_code == 403  # agent can't approve
    allow = api.post(f"/v1/reviews/{review['review']}/approve", headers=ORG)
    assert allow.status_code == 201 and allow.json()["verdict"] == "allow" and allow.json()["supersedes"] == d["decision"]
    assert claims(api, allow.json()["verdict_token"])["supersedes"] == d["decision"]
    assert allow.json()["nonce"] != d["nonce"]
    assert api.post(f"/v1/reviews/{review['review']}/approve", headers=ORG).status_code == 400  # at most one allow
    assert api.get(f"/v1/decisions/{d['decision']}", headers=headers).json()["review"]["status"] == "pending"  # log untouched


def test_idempotency(api, agent):
    headers, *_ = agent
    first = ask(api, headers, 120, **{"Idempotency-Key": "k1"})
    again = ask(api, headers, 120, **{"Idempotency-Key": "k1"})
    assert again.headers["Idempotency-Replayed"] == "true" and again.json() == first.json()
    r = api.post("/v1/authorizations", headers={**headers, "Idempotency-Key": "k1"},
                 json={"amount": 121, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "idempotency_conflict"


def test_5xx_is_never_stored(api, agent):
    headers, *_ = agent
    api.post("/_mock/failure", json={"mode": "5xx"})
    try:
        r = api.post("/v1/authorizations", headers={**headers, "Idempotency-Key": "k5"}, json={})
        assert r.status_code == 503 and r.json()["error"]["code"] == "server_error"
    finally:
        api.post("/_mock/failure", json={"mode": "off"})
    assert "Idempotency-Replayed" not in ask(api, headers, 120, **{"Idempotency-Key": "k5"}).headers


def test_error_envelope(api, agent):
    headers, *_ = agent
    r = api.get("/v1/anything")
    assert r.status_code == 401 and r.json()["error"]["request_id"] == r.headers["X-Request-Id"]
    assert api.post("/v1/mandates", headers=headers, json={}).json()["error"]["code"] == "forbidden"
    assert api.delete("/v1/mandates", headers=ORG).status_code == 400  # not 405
    bad = api.post("/v1/authorizations", headers=headers,
                   json={"amount": "340", "currency": "USD", "recipient": "vendor:x", "category": "saas"})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "invalid_request"
    assert api.get("/v1/decisions/dec_nope", headers=headers).status_code == 404
