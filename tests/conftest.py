"""Shared fixture: a fresh mock agent holding the eval mandate, and a guard that trusts the mock."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from guard.pay import Guard
from integrations.langgraph_agent import MANDATE
from mock_api import app as mock

ORG = {"Authorization": f"Bearer {mock.ORG_KEY}"}
_names = iter(range(10**6))


@pytest.fixture
def sandbox(tmp_path):
    org = TestClient(mock.app, base_url="http://mock")
    a = org.post("/v1/agents", headers=ORG, json={"name": f"agent_{next(_names)}"}).json()
    m = org.post("/v1/mandates", headers=ORG, json={**MANDATE, "agent": a["agent"]}).json()
    api = TestClient(mock.app, base_url="http://mock/v1", headers={"Authorization": f"Bearer {a['agent_key']}"})
    guard = Guard(issuer=mock.ISSUER, agreed_mandates={m["mandate"]}, allowlist={"vendor:acme_saas", "vendor:data_co"},
                  testing_only=True, log_path=tmp_path / "payments.jsonl", http=org)

    def ask(amount, recipient="vendor:acme_saas", category="saas"):
        """Ask the mock for a decision as the agent; returns (decision, payment)."""
        p = {"amount": amount, "currency": "USD", "recipient": recipient, "category": category}
        return guard.authorize(api, task_id=f"t{amount}-{recipient}", **p).decision, p

    return SimpleNamespace(org=org, api=api, guard=guard, ask=ask, mandate=m["mandate"])
