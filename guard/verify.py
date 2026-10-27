"""Verify a verdict token: is it really from the issuer, and is it the approval for this payment?

Runs the 12 checks of docs.saifuro.com/reference/verdict-test-vectors, in their order.
tests/test_vectors.py runs all 138 published vectors against verify().
"""

import base64
import json
import re
from decimal import Decimal

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

CLOCK_SKEW = 60
MAX_TOKEN_LENGTH = 8 * 1024
MAX_JSON_DEPTH = 8  # the vectors need at least 4
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # n
BASE64URL = re.compile(r"[A-Za-z0-9_-]*")
AMOUNT_FORM = re.compile(r"\d{1,15}(\.\d{1,6})?")  # how the issuer writes amounts: no exponent, at most 15.6 digits
KEY_FROM_TOKEN = ("jku", "jwk", "x5u", "x5c")


class Rejected(Exception):
    """The token failed at `step` (1-12, the docs' numbering)."""

    def __init__(self, step: int, why: str):
        super().__init__(f"step {step}: {why}")
        self.step = step


class JsonFloat(Decimal):
    """A JSON number with a fraction or exponent: exact, and remembering how it was written."""

    def __new__(cls, text: str):
        number = super().__new__(cls, text)
        number.text = text
        return number


def no_duplicates(pairs: list) -> dict:
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError("duplicate member name")
    return dict(pairs)


def no_constants(name: str):
    raise ValueError(f"{name} is not JSON")


def depth(value) -> int:
    if isinstance(value, dict):
        value = list(value.values())
    return 1 + max(map(depth, value), default=0) if isinstance(value, list) else 0


def decode_segment(segment: str) -> bytes:
    """Unpadded base64url, strictly: nothing that a lenient decoder would quietly fix."""
    if not BASE64URL.fullmatch(segment):  # urlsafe_b64decode would silently drop stray characters
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
        raise ValueError("not the canonical encoding")
    return raw


def parse_object(raw: bytes) -> dict:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates,
                       parse_float=JsonFloat, parse_constant=no_constants)
    if not isinstance(value, dict) or depth(value) > MAX_JSON_DEPTH:
        raise ValueError("not a JSON object of bounded depth")
    return value


def is_text(value) -> bool:
    return isinstance(value, str) and value != ""


def is_integer(value) -> bool:
    return type(value) is int  # True is an int in Python, and 1791374400.5 is not a NumericDate


def verify(token: str, *, issuers: dict[str, dict], refetch, now: int, mode: str = "settle",
           payment: dict | None = None, agreed_mandates=(), seen_nonces: set | None = None,
           seen_supersedes: set | None = None, testing_only: bool = False,
           received_at: int | None = None, distinguish_test: bool = False,
           audience: str | None = None) -> dict:
    """Return the token's claims, or raise Rejected at the first step that fails.

    issuers           {iss: JWK Set dict}: the only issuers accepted
    refetch(iss)      a fresh JWK Set for iss; called at most once, on an unknown kid, settle mode only
    now               the clock, Unix seconds
    mode              "settle" (all 12 steps) or "record" (a stored verdict: steps 1-7 as the docs say)
    payment           settle: {"amount": decimal string, "currency", "recipient"}, and "category" if known
    agreed_mandates   settle: mandate ids the operator agreed with you (step 8)
    seen_nonces       settle: {(iss, nonce)} already accepted; recorded here, last, on success
    seen_supersedes   settle: {(iss, supersedes)} already accepted; recorded here, last, on success
    testing_only      settle: this verifier is used only for testing (step 3)
    received_at       record: when the verdict was received, or None to skip step 7
    distinguish_test  record: apply step 3
    audience          your own identifier for the aud rule of step 6, or None

    Not thread-safe on its own: the caller holds a lock so the nonce check and record are atomic.
    """
    # Step 1: parse. Bounded size, three unpadded base64url segments, UTF-8, JSON objects, no duplicate names.
    if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
        raise Rejected(1, "not a string of bounded size")
    segments = token.split(".")
    if len(segments) != 3:
        raise Rejected(1, f"{len(segments)} segments, not 3")
    try:
        header = parse_object(decode_segment(segments[0]))
        claims = parse_object(decode_segment(segments[1]))
        signature = decode_segment(segments[2])
    except (ValueError, RecursionError) as e:
        raise Rejected(1, str(e)) from None

    # Step 2: header. Exactly ES256, nothing critical, a kid, and no key taken from the token itself.
    if header.get("alg") != "ES256":
        raise Rejected(2, f"alg {header.get('alg')!r} is not ES256")
    if "crit" in header:
        raise Rejected(2, "crit is not supported")
    kid = header.get("kid")
    if not is_text(kid):
        raise Rejected(2, "kid is missing or not a non-empty string")
    if any(name in header for name in KEY_FROM_TOKEN):
        raise Rejected(2, "the header names a key; keys never come from the token")

    # Step 3: environment. A sandbox key is never a production approval.
    separates_test = not testing_only if mode == "settle" else distinguish_test
    if kid.startswith("sandbox-") and separates_test:
        raise Rejected(3, f"{kid} is a sandbox key")

    # Step 4: issuer and key. The kid is looked up only in the key set of the issuer the token names.
    iss = claims.get("iss")
    if not isinstance(iss, str) or iss not in issuers:
        raise Rejected(4, f"issuer {iss!r} is not accepted")
    matches = [key for key in issuers[iss].get("keys", []) if key.get("kid") == kid]
    if not matches and mode == "settle":  # one refetch, rate-limited by the caller; a stored verdict never refetches
        matches = [key for key in refetch(iss).get("keys", []) if key.get("kid") == kid]
    if len(matches) != 1:
        raise Rejected(4, f"kid {kid} is in the key set {len(matches)} times")
    jwk = matches[0]
    if (jwk.get("kty"), jwk.get("crv"), jwk.get("alg", "ES256"), jwk.get("use", "sig")) != ("EC", "P-256", "ES256", "sig"):
        raise Rejected(4, f"key {kid} is not an ES256 signing key on P-256")

    # Step 5: signature. 64 bytes of R||S, both in [1, n-1], valid for the key over "header.payload".
    if len(signature) != 64:
        raise Rejected(5, f"signature is {len(signature)} bytes, not 64")
    r, s = int.from_bytes(signature[:32]), int.from_bytes(signature[32:])
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):  # R = S = 0 "verified" in Java once (CVE-2022-21449)
        raise Rejected(5, "R or S is outside [1, n-1]")
    try:
        public_key = jwt.PyJWK(jwk).key  # also refuses a point that is not on the curve
        public_key.verify(encode_dss_signature(r, s), f"{segments[0]}.{segments[1]}".encode(), ec.ECDSA(hashes.SHA256()))
    except (jwt.PyJWTError, InvalidSignature) as e:
        raise Rejected(5, f"signature does not verify ({type(e).__name__})") from None

    # Step 6: token kind and structure. A verdict, not a webhook event, with every claim present and typed.
    if "type" in claims or str(claims.get("jti", "")).startswith("evt_"):
        raise Rejected(6, "a webhook event token, not a verdict")
    for name in ("jti", "verdict", "policy_version", "nonce"):
        if not is_text(claims.get(name)):
            raise Rejected(6, f"{name} is missing or empty")
    iat, exp = claims.get("iat"), claims.get("exp")
    if not (is_integer(iat) and is_integer(exp) and exp > iat):
        raise Rejected(6, "iat and exp must be integers, exp after iat")
    if "nbf" in claims and not is_integer(claims["nbf"]):
        raise Rejected(6, "nbf is not an integer")
    request = claims.get("request")
    if not isinstance(request, dict) or not all(is_text(request.get(n)) for n in ("agent", "currency", "recipient", "category")):
        raise Rejected(6, "request is missing or incomplete")
    amount = request.get("amount")
    if not (isinstance(amount, (int, Decimal)) and type(amount) is not bool and amount > 0):
        raise Rejected(6, "request.amount is not a positive number")
    verdict = claims["verdict"]
    if ("mandate" in claims or verdict == "allow") and not is_text(claims.get("mandate")):
        raise Rejected(6, "mandate is missing or empty")
    if "supersedes" in claims and not (verdict == "allow" and is_text(claims["supersedes"])):
        raise Rejected(6, "supersedes belongs only on an allow")
    if "aud" in claims:
        aud = claims["aud"]
        if audience is None or audience not in (aud if isinstance(aud, list) else [aud]):
            raise Rejected(6, "aud does not name this verifier")

    # Step 7: time, with 60 seconds of skew. A stored verdict is judged at the time it was received.
    t = now if mode == "settle" else received_at
    if t is not None:
        if t >= exp + CLOCK_SKEW:
            raise Rejected(7, "expired")
        if iat > t + CLOCK_SKEW:
            raise Rejected(7, "issued in the future")
        if "nbf" in claims and t < claims["nbf"] - CLOCK_SKEW:
            raise Rejected(7, "not valid yet")
    if mode == "record":
        return claims  # steps 8-12 are about settling a payment, not about checking a record

    # Step 8: an approval, under a mandate the operator agreed with us.
    if verdict != "allow":
        raise Rejected(8, f"verdict is {verdict}, not allow")
    if claims["mandate"] not in agreed_mandates:
        raise Rejected(8, f"mandate {claims['mandate']} was not agreed with this operator")

    # Step 9: amount, written the way the issuer writes it and equal to our record by decimal value. Never floats.
    written = amount.text if isinstance(amount, JsonFloat) else str(amount)
    if not AMOUNT_FORM.fullmatch(written):
        raise Rejected(9, f"amount {written} is not written the way the issuer writes amounts")
    if Decimal(written) != Decimal(payment["amount"]):
        raise Rejected(9, f"amount {written} is not the payment's {payment['amount']}")

    # Step 10: currency, case-sensitive.
    if request["currency"] != payment["currency"]:
        raise Rejected(10, f"currency {request['currency']} is not the payment's {payment['currency']}")

    # Step 11: recipient, code point for code point: no normalizing, no trimming.
    if request["recipient"] != payment["recipient"]:
        raise Rejected(11, f"recipient {request['recipient']!r} is not the payment's {payment['recipient']!r}")
    # Not one of the 12 steps: the verdict signs the category too, so when our record has one, it must match.
    if "category" in payment and request["category"] != payment["category"]:
        raise Rejected(11, f"category {request['category']} is not the payment's {payment['category']}")

    # Step 12: replay. Each (issuer, nonce) is accepted once, and a review yields one approval. Recorded last.
    nonce = (iss, claims["nonce"])
    if nonce in seen_nonces:
        raise Rejected(12, "nonce already accepted")
    if "supersedes" in claims and (iss, claims["supersedes"]) in seen_supersedes:
        raise Rejected(12, "this review was already approved once")
    seen_nonces.add(nonce)
    if "supersedes" in claims:
        seen_supersedes.add((iss, claims["supersedes"]))
    return claims
