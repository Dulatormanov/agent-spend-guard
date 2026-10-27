"""Run the eval scenarios against real models; every run, with its full transcript, goes to evals/results.jsonl.

    uv run python -m evals.run --models claude-haiku-5-5 --runs 1        # a cheap pilot
    uv run python -m evals.run --models claude-haiku-5-5 claude-sonnet-5-5 claude-opus-5-5 --runs 10

Hardened tool responses run on every scenario; naive ones too on the evasion scenarios (2, 3, 5, 6, 8).
Each run gets a fresh agent, mandate and guard on the in-process mock. Runs already in the results
file are skipped, so an interrupted run picks up where it stopped. Costs real money: see evals/report.py.
"""

import argparse
import json
import tempfile
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import SimpleNamespace

import httpx
from fastapi.testclient import TestClient
from langchain_core.messages import HumanMessage, messages_to_dict

from evals.scenarios import ALLOWLIST, SCENARIOS, read_vendor_page
from guard.pay import Guard
from integrations.langgraph_agent import MANDATE, build_agent, load_env
from mock_api import app as mock

RESULTS = Path(__file__).parent / "results.jsonl"
ORG = {"Authorization": f"Bearer {mock.ORG_KEY}"}
STEP_LIMIT = 60  # LangGraph steps per turn; a looping agent stops here and the run records it
write_lock = threading.Lock()


def no_answer(request: httpx.Request):
    raise httpx.ReadTimeout("mock: the authorization API did not answer", request=request)


def usage(messages: list) -> dict:
    total = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "refusals": 0}
    for m in messages:
        if u := getattr(m, "usage_metadata", None):
            details = u.get("input_token_details", {})
            total["input"] += u["input_tokens"]
            total["output"] += u["output_tokens"]
            total["cache_read"] += details.get("cache_read", 0)
            total["cache_write"] += details.get("cache_creation", 0)
        total["refusals"] += getattr(m, "response_metadata", {}).get("stop_reason") == "refusal"
    return total


def run_once(scenario, model: str, style: str, n: int, log_dir: Path) -> dict:
    org = TestClient(mock.app, base_url="http://mock")
    agent_id = org.post("/v1/agents", headers=ORG, json={"name": f"eval_{uuid.uuid4().hex[:12]}"}).json()
    mandate = org.post("/v1/mandates", headers=ORG, json={**MANDATE, "agent": agent_id["agent"]}).json()["mandate"]
    headers = {"Authorization": f"Bearer {agent_id['agent_key']}"}
    if scenario.timeout:
        api = httpx.Client(base_url="http://mock/v1", headers=headers, transport=httpx.MockTransport(no_answer))
    else:
        api = TestClient(mock.app, base_url="http://mock/v1", headers=headers)
    guard = Guard(issuer=mock.ISSUER, agreed_mandates={mandate}, allowlist=ALLOWLIST, testing_only=True,
                  log_path=log_dir / f"{uuid.uuid4().hex}.jsonl", http=org)
    ctx = SimpleNamespace(org=org, org_headers=ORG, api=api, mandate=mandate)
    run_id = f"{model}|{style}|{scenario.id}|{n}"
    agent = build_agent(model, guard, api, task_id=run_id, style=style, extra_tools=[read_vendor_page])

    messages, error, started = [], None, time.time()
    try:
        for turn, text in enumerate(scenario.turns):
            if scenario.before_turn:
                scenario.before_turn(turn, ctx)
            guard.write({"event": "turn", "n": turn})
            messages.append(HumanMessage(text() if callable(text) else text))
            messages = agent.invoke({"messages": messages}, {"recursion_limit": STEP_LIMIT})["messages"]
    except Exception:
        error = traceback.format_exc(limit=3)
    events = [json.loads(line) for line in guard.log_path.read_text().splitlines()]
    transcript = messages_to_dict(messages)
    verdict = scenario.judge(events, transcript)
    if error:
        verdict["passed"] = None  # a crashed run measures nothing
    return {"run": run_id, "model": model, "style": style, "scenario": scenario.id, "name": scenario.name, "n": n,
            **verdict, "error": error, "seconds": round(time.time() - started, 1), "usage": usage(messages),
            "events": events, "transcript": transcript}


def main():
    load_env()
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+", required=True)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--scenarios", type=int, nargs="*", help="only these scenario ids")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    done = {json.loads(line)["run"] for line in RESULTS.read_text().splitlines()} if RESULTS.exists() else set()
    jobs = [(s, model, style, n)
            for model in args.models
            for s in SCENARIOS if not args.scenarios or s.id in args.scenarios
            for style in (["hardened", "naive"] if s.evasion else ["hardened"])
            for n in range(args.runs)
            if f"{model}|{style}|{s.id}|{n}" not in done]
    print(f"{len(jobs)} runs to do ({len(done)} already in {RESULTS.name})", flush=True)

    with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(args.workers) as pool:
        futures = [pool.submit(run_once, *job, Path(tmp)) for job in jobs]
        for i, future in enumerate(as_completed(futures), 1):
            r = future.result()
            with write_lock, RESULTS.open("a") as out:
                out.write(json.dumps(r) + "\n")
            outcome = {True: "pass", False: "FAIL", None: "n/a"}[r["passed"]]
            print(f"[{i}/{len(jobs)}] {r['run']}: {outcome}"
                  f"{' bypass=' + str(r['bypass_attempts']) if r.get('bypass_attempts') else ''}"
                  f"{' ERROR' if r['error'] else ''}", flush=True)


if __name__ == "__main__":
    main()
