"""Local mock of the Saifuro /v1 API, built from docs.saifuro.com as fetched on 2026-10-27.

Unofficial, not affiliated with Saifuro. It copies the documented behavior of the
endpoints this project uses. Everything under /_mock exists only here, never in the
real API. Reason strings other than the two the docs print are this mock's wording.

Run: uv run uvicorn mock_api.app:app --port 8402
"""

import asyncio
import hashlib
import json
import os
import secrets
import time
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Annotated, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from jwt.algorithms import ECAlgorithm
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException

ISSUER = os.environ.get("MOCK_ISSUER", "http://127.0.0.1:8402")
ORG_KEY = os.environ.get("MOCK_ORG_KEY", "sk_sandbox_" + "0" * 32)
KID = "sandbox-mock-1"
SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())  # ponytail: new key per process; tokens live 5 minutes anyway
JWKS = {"keys": [{**ECAlgorithm.to_jwk(SIGNING_KEY.public_key(), as_dict=True), "use": "sig", "alg": "ES256", "kid": KID}]}
POLICY_VERSION = f"pol_{date.today().isoformat()}.1"
TOKEN_LIFETIME = 300
VELOCITY_LIMIT, VELOCITY_WINDOW = 10, 60  # fixed in the engine, not configurable
DAY = 86400


def now() -> float:  # tests monkeypatch this
    return time.time()


def iso(t: float) -> str:
    return datetime.fromtimestamp(int(t), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ponytail: in-memory state, lost on restart; evals use a fresh agent per run instead of a reset
keys: dict[str, str | None] = {ORG_KEY: None}  # API key -> agent id, None for the organization key
agents: dict[str, dict] = {}
mandates: dict[str, dict] = {}
decisions: dict[str, dict] = {}
reviews: dict[str, dict] = {}
log: list[tuple[float, str, str | None, str, Decimal]] = []  # (time, agent, mandate, verdict, amount)
idempotency: dict[tuple[str, str], tuple[str, float, int, dict]] = {}  # (API key, Idempotency-Key) -> (body hash, time, status, body)
enforcement = {"mode": "enforce", "since": iso(now())}  # a new sandbox starts in enforce
failure = {"mode": "off", "seconds": 15.0}  # mock-only switch, see POST /_mock/failure

app = FastAPI(title="Saifuro API mock (unofficial)")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def error(request: Request, status: int, code: str, message: str) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "request_id": request.state.request_id}}
    return JSONResponse(body, status)


@app.exception_handler(ApiError)
async def on_api_error(request: Request, e: ApiError):
    return error(request, e.status, e.code, e.message)


@app.exception_handler(RequestValidationError)
async def on_validation_error(request: Request, e: RequestValidationError):
    first = e.errors()[0]
    where = ".".join(str(p) for p in first["loc"][1:]) or "body"
    return error(request, 400, "invalid_request", f"{where}: {first['msg']}")


@app.exception_handler(HTTPException)
async def on_http_error(request: Request, e: HTTPException):
    if e.status_code == 405:  # the API answers an unsupported method with 400, not 405
        return error(request, 400, "invalid_request", f"{request.method} is not supported on {request.url.path}")
    return error(request, 404, "not_found", "No such object")


@app.middleware("http")
async def api_middleware(request: Request, call_next):
    request.state.request_id = "req_" + secrets.token_hex(16)
    response = await handle(request, call_next)
    response.headers["X-Request-Id"] = request.state.request_id
    return response


def canonical(body: bytes) -> bytes:
    try:
        return json.dumps(json.loads(body), sort_keys=True).encode()
    except ValueError:
        return body


async def handle(request: Request, call_next):
    if not request.url.path.startswith("/v1/"):
        return await call_next(request)
    if failure["mode"] == "5xx":
        return error(request, 503, "server_error", "mock failure switch is set to 5xx")
    if failure["mode"] == "timeout":
        await request.body()  # read before the client gives up, so the request still gets decided
        await asyncio.sleep(failure["seconds"])  # then answers normally, after the client has given up
    api_key = request.headers.get("authorization", "").removeprefix("Bearer ")
    if api_key not in keys:
        return error(request, 401, "unauthorized", "Missing or revoked key")
    request.state.api_key, request.state.agent = api_key, keys[api_key]
    if request.method != "POST":
        return await call_next(request)

    body = await request.body()
    if len(body) > 64 * 1024:
        return error(request, 400, "invalid_request", "Request body is over 64 KB")
    idem = request.headers.get("idempotency-key")
    if idem is None:
        return await call_next(request)
    if len(idem) > 255:
        return error(request, 400, "invalid_request", "Idempotency-Key is over 255 characters")
    fingerprint = hashlib.sha256(request.url.path.encode() + b"\0" + canonical(body)).hexdigest()
    stored = idempotency.get((api_key, idem))
    if stored and now() - stored[1] < DAY:
        if stored[0] != fingerprint:
            return error(request, 409, "idempotency_conflict", "Idempotency-Key was used with a different body")
        return JSONResponse(stored[3], stored[2], headers={"Idempotency-Replayed": "true"})

    response = await call_next(request)
    if response.status_code >= 500 or response.status_code in (401, 403, 429):  # never stored
        return response
    content = b"".join([chunk async for chunk in response.body_iterator])
    # ponytail: two concurrent requests with one new key can both run; a lock per key if that matters
    idempotency[(api_key, idem)] = (fingerprint, now(), response.status_code, json.loads(content))
    return Response(content, response.status_code, headers=dict(response.headers))


def org_only(request: Request):
    if request.state.agent is not None:
        raise ApiError(403, "forbidden", "This endpoint needs an organization key")


ORG = [Depends(org_only)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


Num = int | float
Metadata = Annotated[dict[str, Annotated[str, Field(max_length=500)]], Field(max_length=20)]


class AgentIn(Strict):
    name: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    metadata: Metadata | None = None


class LimitsIn(Strict):
    per_transaction: Num = Field(gt=0)
    per_month: Num | None = Field(None, gt=0)
    currency: str = Field(min_length=1, max_length=128)


class EscrowIn(Strict):
    required_above: str  # stored, not enforced (docs: known gaps)


class MandateIn(Strict):
    principal: str = Field(min_length=1)
    agent: str
    limits: LimitsIn
    categories: list[Annotated[str, Field(max_length=128)]]
    review_above: Num | None = None
    expires: date = Field(strict=False)  # JSON carries the date as a string
    escrow: EscrowIn | None = None


class AuthorizationIn(Strict):
    amount: Num = Field(gt=0)
    currency: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=1024)
    category: str = Field(min_length=1, max_length=128)
    protocol: Literal["x402", "mpp", "acp", "ap2", "card"] | None = None  # usage reporting only, never returned
    agent: str | None = None
    metadata: Metadata | None = None


class EnforcementIn(Strict):
    mode: Literal["observe", "enforce"]


def money(x: Num | Decimal) -> str:
    d = Decimal(str(x))
    return f"{d:.2f}" if d == round(d, 2) else str(d)


def plain(x: Num) -> Num:
    return int(x) if x == int(x) else x  # 340.00 is echoed as 340, as in the docs


def mandate_view(m: dict) -> dict:
    if m["status"] == "active" and date.fromisoformat(m["expires"]) < datetime.fromtimestamp(now(), timezone.utc).date():
        return {**m, "status": "expired"}
    return m


def allowed_in_30_days(mandate_id: str, t: float) -> Decimal:
    return sum((a for when, _, mid, v, a in log if mid == mandate_id and v == "allow" and t - when < 30 * DAY), Decimal(0))


def check(m: dict, agent: str, amount: Decimal, category: str, t: float) -> tuple[str, str]:
    mid, limits, status = m["mandate"], m["limits"], mandate_view(m)["status"]
    if status == "revoked":
        return "deny_revoked", f"mandate {mid} was revoked"
    if status == "expired":
        return "deny_expired", f"mandate {mid} expired {m['expires']}"
    if category not in m["categories"]:
        return "deny_category", f"category {category} is not allowed by mandate {mid}"
    if amount > Decimal(str(limits["per_transaction"])):
        return "deny_limit", f"amount {money(amount)} exceeds per_transaction limit {money(limits['per_transaction'])}"
    if "per_month" in limits:
        total = allowed_in_30_days(mid, t) + amount
        if total > Decimal(str(limits["per_month"])):
            return "deny_limit", f"30-day total {money(total)} exceeds per_month limit {money(limits['per_month'])}"
    if sum(1 for when, a, *_ in log if a == agent and t - when < VELOCITY_WINDOW) >= VELOCITY_LIMIT:
        return "deny_velocity", f"agent {agent} already had {VELOCITY_LIMIT} decisions in the last {VELOCITY_WINDOW} seconds"
    if "review_above" in m and amount > Decimal(str(m["review_above"])):
        return "review", f"amount {money(amount)} is above review_above {money(m['review_above'])}"
    return "allow", f"within mandate {mid}"


def issue(request_echo: dict, verdict: str, reason: str, mandate: dict | None,
          metadata: dict | None = None, supersedes: str | None = None) -> dict:
    t = int(now())
    decision_id, nonce = "dec_" + secrets.token_hex(6), "n_" + secrets.token_hex(8)
    claims = {"iss": ISSUER, "jti": decision_id, "iat": t, "exp": t + TOKEN_LIFETIME, "verdict": verdict,
              "policy_version": POLICY_VERSION, "nonce": nonce, "request": request_echo}
    d = {"decision": decision_id, "request": request_echo, "verdict": verdict, "reason": reason}
    if mandate:
        claims["mandate"] = d["mandate"] = mandate["mandate"]
    if supersedes:
        claims["supersedes"] = supersedes
    d |= {"policy_version": POLICY_VERSION, "nonce": nonce, "mode": enforcement["mode"], "issued_at": iso(t)}
    if verdict == "allow":
        d["expires_at"] = iso(t + TOKEN_LIFETIME)
    d["verdict_token"] = jwt.encode(claims, SIGNING_KEY, algorithm="ES256", headers={"kid": KID})
    if supersedes:
        d["supersedes"] = supersedes
    if verdict == "review":
        review_id = "rev_" + secrets.token_hex(6)
        d["review"] = {"review": review_id, "waits_for": mandate["principal"], "expires_at": iso(t + DAY), "status": "pending"}
        reviews[review_id] = {**d["review"], "decision": decision_id, "expires_at_ts": t + DAY}
    if metadata:
        d["metadata"] = metadata
    decisions[decision_id] = d
    log.append((t, request_echo["agent"], d.get("mandate"), verdict, Decimal(str(request_echo["amount"]))))
    return d


@app.get("/.well-known/jwks.json")
def jwks():
    return JSONResponse(JWKS, headers={"Cache-Control": "max-age=300"})


@app.post("/v1/agents", status_code=201, dependencies=ORG)
def create_agent(body: AgentIn):
    agent_id = "agt_" + body.name
    if agent_id in agents:
        raise ApiError(400, "invalid_request", f"agent name {body.name} is already taken")
    agents[agent_id] = {"agent": agent_id, "name": body.name, "status": "active", "created_at": iso(now())}
    if body.metadata:
        agents[agent_id]["metadata"] = body.metadata
    agent_key = "ak_sandbox_" + secrets.token_hex(16)
    keys[agent_key] = agent_id
    return {**agents[agent_id], "agent_key": agent_key}  # shown once


@app.post("/v1/mandates", status_code=201, dependencies=ORG)
def create_mandate(body: MandateIn):
    if body.agent not in agents:
        raise ApiError(400, "invalid_request", f"unknown agent {body.agent}")
    mandate_id = "mnd_" + secrets.token_hex(4)
    mandates[mandate_id] = {"mandate": mandate_id, **body.model_dump(mode="json", exclude_none=True),
                            "status": "active", "created_at": iso(now())}
    return mandate_view(mandates[mandate_id])


@app.post("/v1/mandates/{mandate_id}/revoke", dependencies=ORG)
def revoke_mandate(mandate_id: str):
    m = mandates.get(mandate_id)
    if not m:
        raise ApiError(404, "not_found", "No such object")
    if m["status"] == "revoked":
        raise ApiError(400, "invalid_request", f"mandate {mandate_id} is already revoked")
    m |= {"status": "revoked", "revoked_at": iso(now())}
    return m


@app.post("/v1/authorizations", status_code=201)
def create_authorization(body: AuthorizationIn, request: Request):
    agent = request.state.agent or body.agent  # an agent key decides; `agent` is ignored on one
    if not agent:
        raise ApiError(400, "invalid_request", "agent is required on an organization key")
    if agent not in agents:
        raise ApiError(400, "invalid_request", f"unknown agent {agent}")
    echo = {"agent": agent, "amount": plain(body.amount), "currency": body.currency,
            "recipient": body.recipient, "category": body.category}
    candidates = [m for m in mandates.values() if m["agent"] == agent and m["limits"]["currency"] == body.currency]
    if not candidates:
        return issue(echo, "deny_no_mandate", f"no mandate for {agent} in {body.currency}", None, body.metadata)
    amount, t = Decimal(str(body.amount)), now()
    results = [(*check(m, agent, amount, body.category, t), m) for m in candidates]  # in order of creation
    verdict, reason, mandate = next((r for r in results if r[0] == "allow"), None) \
        or next((r for r in results if r[0] == "review"), None) or results[0]
    return issue(echo, verdict, reason, mandate, body.metadata)


def pending_review(review_id: str) -> dict:
    r = reviews.get(review_id)
    if not r:
        raise ApiError(404, "not_found", "No such object")
    if r["status"] == "pending" and now() > r["expires_at_ts"]:
        r["status"] = "expired"
    if r["status"] != "pending":
        raise ApiError(400, "invalid_request", f"review {review_id} is {r['status']}")
    return r


@app.post("/v1/reviews/{review_id}/approve", status_code=201, dependencies=ORG)
def approve_review(review_id: str):
    r = pending_review(review_id)
    original = decisions[r["decision"]]
    m = mandates[original["mandate"]]
    status = mandate_view(m)["status"]
    if status != "active":
        raise ApiError(400, "invalid_request", f"mandate {m['mandate']} is {status}")
    amount = Decimal(str(original["request"]["amount"]))
    if "per_month" in m["limits"] and allowed_in_30_days(m["mandate"], now()) + amount > Decimal(str(m["limits"]["per_month"])):
        raise ApiError(400, "invalid_request", f"approval would exceed per_month limit {money(m['limits']['per_month'])}")
    r["status"] = "approved"
    return issue(original["request"], "allow", f"review {review_id} approved", m,
                 original.get("metadata"), supersedes=original["decision"])


@app.post("/v1/reviews/{review_id}/deny", dependencies=ORG)
def deny_review(review_id: str):
    r = pending_review(review_id)
    r["status"] = "denied"
    return {k: r[k] for k in ("review", "waits_for", "expires_at", "status")}


@app.get("/v1/decisions/{decision_id}")
def get_decision(decision_id: str, request: Request):
    d = decisions.get(decision_id)
    if not d or request.state.agent not in (None, d["request"]["agent"]):  # "not yours" is a 404
        raise ApiError(404, "not_found", "No such object")
    return d


@app.get("/v1/enforcement", dependencies=ORG)
def get_enforcement():
    return enforcement


@app.post("/v1/enforcement", dependencies=ORG)
def set_enforcement(body: EnforcementIn):
    if body.mode != enforcement["mode"]:
        enforcement.update(mode=body.mode, since=iso(now()))
    return enforcement


class FailureIn(BaseModel):
    mode: Literal["off", "5xx", "timeout"]
    seconds: float = 15.0


@app.post("/_mock/failure")
def set_failure(body: FailureIn):
    """MOCK ONLY. Makes every /v1 request return 503, or wait `seconds` before answering."""
    failure.update(body.model_dump())
    return failure
