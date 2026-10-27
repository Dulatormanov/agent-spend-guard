"""MCP server: payment tools for any MCP client, guarded the same way as the LangGraph agent.

Tools: check_payment, get_decision, and a guarded pay. The server holds only the agent key. There is
deliberately no approve tool: approving a review needs the organization key, and an agent that could
approve its own review would skip the person the review is waiting for.

Configuration (environment or .env):
    SAIFURO_BASE_URL, SAIFURO_AGENT_KEY (ak_...), SAIFURO_ISSUER
    SAIFURO_AGREED_MANDATES, SAIFURO_ALLOWLIST   comma-separated
    SAIFURO_TESTING_ONLY=1                       only against a sandbox or the mock
Run: uv run python -m mcp_server.server   (stdio; see mcp_server/setup_demo.py for the mock)
"""

import os
import sys
import uuid
from pathlib import Path

import httpx
from mcp.server.mcpserver import MCPServer

from guard.client import Outcome, make_client
from guard.pay import Guard
from integrations.langgraph_agent import hardened, load_env


def make_server(guard: Guard, api: httpx.Client, task_id: str) -> MCPServer:
    server = MCPServer("agent-spend-guard", instructions=(
        "Before paying anyone, call check_payment with the exact payment. Pay with pay and the decision_id "
        "it returned. A review waits for a person: use get_decision to see whether it was approved."))
    decisions: dict[str, dict] = {}  # what this server fetched; pay never takes a decision from the client

    @server.tool()
    def check_payment(amount: float, currency: str, recipient: str, category: str) -> str:
        """Ask whether a payment is allowed. Call it before every payment, with the exact amount,
        currency (e.g. USD), recipient (e.g. vendor:acme_saas) and spend category (e.g. saas)."""
        out = guard.authorize(api, task_id=task_id, amount=amount, currency=currency, recipient=recipient,
                              category=category)
        if not out.decision:
            return hardened(out)
        decisions[out.decision["decision"]] = out.decision
        if out.decision["verdict"] == "review":
            return f"{hardened(out)} Its decision_id is {out.decision['decision']}; get_decision shows when it's approved."
        return hardened(out)

    @server.tool()
    def get_decision(decision_id: str) -> str:
        """Read one of your decisions. For a review, says whether a person has approved it yet."""
        r = api.get(f"/decisions/{decision_id}")
        if r.status_code != 200:
            return f"No decision {decision_id} (HTTP {r.status_code})."
        d = decisions[decision_id] = r.json()
        if d["verdict"] != "review":
            return hardened(Outcome(d, f"{d['verdict']}: {d['reason']}"))
        # There is no reviews endpoint: an approval is a new allow whose `supersedes` names the review.
        approvals = api.get("/decisions", params={"verdict": "allow"}).json()["data"]
        approval = next((a for a in approvals if a.get("supersedes") == decision_id), None)
        if approval is None:
            return (f"Still waiting: {d['review']['waits_for']} hasn't approved {decision_id}. "
                    "Do not pay. Tell the user it is waiting for approval.")
        decisions[approval["decision"]] = approval
        return hardened(Outcome(approval, f"allow: review {decision_id} approved"))

    @server.tool()
    def pay(decision_id: str, amount: float, currency: str, recipient: str, category: str) -> str:
        """Pay a vendor. decision_id comes from check_payment or get_decision; the other values must
        be exactly the ones it approved."""
        result = guard.pay(decisions.get(decision_id),
                           {"amount": amount, "currency": currency, "recipient": recipient, "category": category})
        if result.paid:
            return result.message
        return f"{result.message}. Nothing was paid. Do not try again with changed values; tell the user."

    return server


def main():
    load_env()
    env = os.environ
    if not env.get("SAIFURO_AGENT_KEY", "").startswith("ak_"):
        sys.exit("SAIFURO_AGENT_KEY must be an agent key (ak_...). Never give this server an organization key.")
    guard = Guard(issuer=env.get("SAIFURO_ISSUER", "http://127.0.0.1:8402"),
                  agreed_mandates=set(env["SAIFURO_AGREED_MANDATES"].split(",")),
                  allowlist=set(env["SAIFURO_ALLOWLIST"].split(",")),
                  testing_only=env.get("SAIFURO_TESTING_ONLY") == "1",
                  log_path=Path(env.get("PAYMENTS_LOG", "payments.jsonl")))
    make_server(guard, make_client(), task_id=uuid.uuid4().hex).run("stdio")


if __name__ == "__main__":
    main()
