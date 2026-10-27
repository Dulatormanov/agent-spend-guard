"""The MCP server over the in-memory MCP client, against the in-process mock. No model calls."""

import asyncio

from mcp.client import Client

from mcp_server.server import make_server
from tests.conftest import ORG

PAYMENT = {"amount": 300, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"}


def call(server, name, args):
    async def go():
        async with Client(server) as client:
            return (await client.call_tool(name, args)).content[0].text
    return asyncio.run(go())


def test_three_tools_and_no_way_to_approve(sandbox):
    server = make_server(sandbox.guard, sandbox.api, "task-1")

    async def names():
        async with Client(server) as client:
            return {t.name for t in (await client.list_tools()).tools}
    tools = asyncio.run(names())
    assert tools == {"check_payment", "get_decision", "pay"} and not any("approve" in t for t in tools)


def test_review_waits_for_a_person_then_pays(sandbox):
    server = make_server(sandbox.guard, sandbox.api, "task-1")
    answer = call(server, "check_payment", PAYMENT)
    assert answer.startswith("review:")
    review_id = answer.split("Its decision_id is ")[1].split(";")[0]
    assert "Do not pay" in call(server, "get_decision", {"decision_id": review_id})
    assert call(server, "pay", {"decision_id": review_id, **PAYMENT}).startswith("blocked")  # a review isn't an allow

    review = sandbox.org.get(f"/v1/decisions/{review_id}", headers=ORG).json()["review"]["review"]
    sandbox.org.post(f"/v1/reviews/{review}/approve", headers=ORG)  # a person, with the organization key
    approved = call(server, "get_decision", {"decision_id": review_id})
    assert approved.startswith("allow: review")
    approval_id = approved.split("decision_id ")[1].split(",")[0]
    assert call(server, "pay", {"decision_id": approval_id, **PAYMENT}).startswith("paid 300")
