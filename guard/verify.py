"""Verify a verdict token. Dulat writes verify(); this file only fixes its contract.

Step numbers are the 12 checks in docs.saifuro.com/reference/verdict-test-vectors.
tests/test_vectors.py runs all 138 published vectors against this function.
"""

CLOCK_SKEW = 60


class Rejected(Exception):
    """The token failed at `step` (1-12, the docs' numbering)."""

    def __init__(self, step: int, why: str):
        super().__init__(f"step {step}: {why}")
        self.step = step


def verify(token: str, *, issuers: dict[str, dict], refetch, now: int, mode: str = "settle",
           payment: dict | None = None, agreed_mandates=(), seen_nonces: set | None = None,
           seen_supersedes: set | None = None, testing_only: bool = False,
           received_at: int | None = None, distinguish_test: bool = False,
           audience: str | None = None) -> dict:
    """Return the token's claims, or raise Rejected at the first step that fails.

    issuers           {iss: JWK Set dict}: the only issuers accepted
    refetch(iss)      a fresh JWK Set for iss; at most once, on an unknown kid, settle mode only
    now               the clock, Unix seconds
    mode              "settle" (all 12 steps) or "record" (a stored verdict, see the docs)
    payment           settle: {"amount": decimal string, "currency": ..., "recipient": ...}
    agreed_mandates   settle: mandate ids the operator agreed with you (step 8)
    seen_nonces       settle: {(iss, nonce)} already accepted; add to it last, on success (step 12)
    seen_supersedes   settle: {(iss, supersedes)} already accepted; add to it last, on success
    testing_only      settle: this verifier is used only for testing (step 3)
    received_at       record: when the verdict was received, or None to skip step 7
    distinguish_test  record: apply step 3
    audience          your own identifier for the aud rule of step 6, or None
    """
    raise NotImplementedError("Dulat writes verify(); run tests/test_vectors.py")
