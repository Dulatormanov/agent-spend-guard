"""verify() against the 138 published verdict test vectors, plus one production-signed token."""

import json
from pathlib import Path

import pytest

from guard.verify import Rejected, verify

REF = Path(__file__).parent.parent / "reference"
DATA = json.loads((REF / "verdict-test-vectors.json").read_text())  # test keys only, never real verification


def outcome(fn) -> tuple[bool, int | None]:
    try:
        fn()
        return True, None
    except Rejected as e:
        return False, e.step


@pytest.mark.parametrize("v", DATA["vectors"], ids=lambda v: v["id"])
def test_vector(v):
    keysets = {iss: DATA["keySets"][name] for iss, name in v["issuers"].items()}
    refetches = []

    def refetch(iss):
        refetches.append(iss)
        return DATA["keySets"][v.get("refetchWouldReturn") or v["issuers"][iss]]

    seen_nonces, seen_supersedes = {tuple(p) for p in v.get("seenNonces", [])}, {tuple(p) for p in v.get("seenSupersedes", [])}
    claims = {}

    def run():
        claims.update(verify(
            v["token"], issuers=keysets, refetch=refetch, now=v["now"], mode=v["mode"], audience=v["audience"],
            payment=v.get("payment"), agreed_mandates=v.get("agreedMandates", ()),
            seen_nonces=seen_nonces, seen_supersedes=seen_supersedes, testing_only=v.get("testingOnly", False),
            received_at=v.get("receivedAt"), distinguish_test=v.get("distinguishTest", False)))

    got = outcome(run)
    expected = (v["expected"]["valid"], v["expected"]["step"])
    assert got == expected, f"{v['description']} {v['expected'].get('note', '')}"
    assert len(refetches) <= (1 if v["mode"] == "settle" else 0), "one refetch at most, none for a stored verdict"
    if got[0] and v["mode"] == "settle":
        assert (claims["iss"], claims["nonce"]) in seen_nonces, "an accepted nonce is recorded"


# From docs.saifuro.com/reference/verify-a-verdict ("A token to try it on"): signed with the
# production key verdict-2026-09 on 2026-09-03 08:43 UTC, before request.currency was signed.
SAMPLE = (
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InZlcmRpY3QtMjAyNi0wOSJ9"
    ".eyJpc3MiOiJodHRwczovL3ZlcmRpY3RzLnNhaWZ1cm8uY29tIiwianRpIjoiZGVjXzViMmUiLCJpYXQiOjE3ODg0MjQ5ODAsImV4cCI6MTc4ODQy"
    "NTI4MCwidmVyZGljdCI6ImFsbG93IiwibWFuZGF0ZSI6Im1uZF83ZjNhIiwicG9saWN5X3ZlcnNpb24iOiJwb2xfMjAyNi0wOC0xMi4zIiwibm9uY2Ui"
    "OiJuXzlkMDJjNmU0IiwicmVxdWVzdCI6eyJhZ2VudCI6ImFndF9wcm9jdXJlbWVudF8wMSIsImFtb3VudCI6MzQwLCJyZWNpcGllbnQiOiJ2ZW5kb3I6"
    "YWNtZV9zYWFzIiwiY2F0ZWdvcnkiOiJzYWFzIn19"
    ".oV4a02jtE2oEKvnSXxQ-YqJcpp8UvFZiuh3AeTb5Iy5Ony9jC1AA7EX-YPSKDuSFPxSNS4SlXLtU9-j0J36cbQ"
)


def test_production_sample_token():
    jwks = json.loads((REF / "jwks-snapshot-2026-10-27.json").read_text())
    got = outcome(lambda: verify(
        SAMPLE, issuers={"https://verdicts.saifuro.com": jwks}, refetch=lambda iss: jwks, now=1788425100,
        payment={"amount": "340", "currency": "USD", "recipient": "vendor:acme_saas"}, agreed_mandates=["mnd_7f3a"],
        seen_nonces=set(), seen_supersedes=set()))
    # The signature (step 5) passes; the token has no request.currency, which step 6 requires.
    assert got == (False, 6)
