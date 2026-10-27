"""The agent's tools run through the guard, in both response styles. A scripted model: no API calls."""

import json

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, ToolMessage

from integrations.langgraph_agent import build_agent, make_tools

PAYMENT = {"amount": 120, "currency": "USD", "recipient": "vendor:acme_saas", "category": "saas"}


class ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def tools(sandbox, style):
    ask, pay = make_tools(sandbox.guard, sandbox.api, task_id="task-1", style=style)
    return ask, pay


def test_hardened_allow_then_pay(sandbox):
    ask, pay = tools(sandbox, "hardened")
    answer = ask.invoke(PAYMENT)
    assert answer.startswith("allow:") and "Call pay once" in answer
    decision_id = answer.split("decision_id ")[1].split(",")[0]
    assert pay.invoke({"decision_id": decision_id, **PAYMENT}).startswith("paid 120")


def test_hardened_denial_says_what_not_to_do(sandbox):
    ask, _ = tools(sandbox, "hardened")
    answer = ask.invoke({**PAYMENT, "amount": 720})
    assert answer.startswith("deny_limit:") and "split it into smaller payments" in answer


def test_naive_returns_raw_json(sandbox):
    ask, pay = tools(sandbox, "naive")
    decision = json.loads(ask.invoke(PAYMENT))
    assert decision["verdict"] == "allow" and "verdict_token" in decision
    assert json.loads(pay.invoke({"decision_id": decision["decision"], **PAYMENT}))["paid"]


def test_a_decision_id_the_model_made_up_pays_nothing(sandbox):
    _, pay = tools(sandbox, "hardened")
    answer = pay.invoke({"decision_id": "dec_madeup", **PAYMENT})
    assert answer.startswith("blocked: no verdict") and not sandbox.guard.log_path.read_text().count('"paid": true')


def test_agent_loop_runs_tools_through_the_guard(sandbox):
    model = ScriptedModel(messages=iter([
        AIMessage(content="", tool_calls=[{"name": "request_authorization", "args": {**PAYMENT, "amount": 720}, "id": "c1"}]),
        AIMessage(content="The purchase was denied: it is over the 500 USD limit."),
    ]))
    result = build_agent(model, sandbox.guard, sandbox.api, task_id="task-1").invoke(
        {"messages": [{"role": "user", "content": "Buy the $720 dataset"}]})
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert len(tool_messages) == 1 and tool_messages[0].content.startswith("deny_limit:")
