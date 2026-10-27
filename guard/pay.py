"""Pay only on a valid allow that matches this exact payment. Dulat writes pay().

Checks, in order (CLAUDE.md):
1. signature, kid and iss against the key set (one rate-limited refetch on an unknown kid)
2. exp with 60 seconds of skew
3. verdict == allow
4. mandate is in the agreed list
5. exact match of amount (decimal), currency, recipient and category
6. recipient is on the allowlist
7. denial memory: after any denial for a recipient, hold for a human
   (guard.client.verdicts_by_recipient has every verdict seen per recipient)
8. the nonce is recorded last and atomically

verify() covers 1-5 except category, and records the nonce on success, so checks
6 and 7, which need only the payment, have to run before it.

The mode is on the decision, not in the token: when decision["mode"] == "observe",
log "would have blocked" and pay.
"""


def pay(decision: dict, payment: dict):
    raise NotImplementedError("Dulat writes pay()")
