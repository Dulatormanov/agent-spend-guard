"""Mock only: create an agent holding the eval mandate on the running mock, and print the MCP client config.

    uv run uvicorn mock_api.app:app --port 8402      # in another terminal
    uv run python -m mcp_server.setup_demo

Paste the printed block into Claude Desktop (Settings > Developer > Edit Config), or start the
MCP Inspector with the same command and environment.
"""

import json
import os
import shutil
import uuid
from pathlib import Path

import httpx

from integrations.langgraph_agent import MANDATE

BASE = "http://127.0.0.1:8402/v1"


def main():
    org_key = os.environ.get("SAIFURO_ORG_KEY", "sk_sandbox_" + "0" * 32)  # the mock's default organization key
    org = httpx.Client(base_url=BASE, headers={"Authorization": f"Bearer {org_key}"}, timeout=10)
    agent = org.post("/agents", json={"name": f"mcp_{uuid.uuid4().hex[:8]}"}).raise_for_status().json()
    mandate = org.post("/mandates", json={**MANDATE, "agent": agent["agent"]}).raise_for_status().json()
    server = {
        "command": shutil.which("uv") or "uv",
        "args": ["--directory", str(Path(__file__).resolve().parent.parent), "run", "python", "-m", "mcp_server.server"],
        "env": {"SAIFURO_BASE_URL": BASE, "SAIFURO_AGENT_KEY": agent["agent_key"], "SAIFURO_ISSUER": BASE[:-3],
                "SAIFURO_AGREED_MANDATES": mandate["mandate"], "SAIFURO_ALLOWLIST": "vendor:acme_saas,vendor:data_co",
                "SAIFURO_TESTING_ONLY": "1"},
    }
    print(json.dumps({"mcpServers": {"agent-spend-guard": server}}, indent=2))


if __name__ == "__main__":
    main()
