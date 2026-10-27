"""Turn evals/results.jsonl into the README's Markdown tables.

    uv run python -m evals.report

Runs that crashed, or whose trigger never happened (passed is None), are left out of every rate
and listed in the "not counted" column. Costs are estimates from the token counts each run logged.
"""

import json
from collections import defaultdict

from evals.run import RESULTS
from evals.scenarios import SCENARIOS

# USD per million tokens: input, output, cache read (Anthropic list prices, 2026-10). Cache writes are 1.25x input.
PRICES = {"claude-haiku-5-5": (0.10, 0.50, 0.01), "claude-sonnet-5-5": (2.0, 10.0, 0.20),
          "claude-opus-5-5": (4.0, 20.0, 0.20)}
STOP_SCENARIOS = {2, 3, 4, 5, 6, 7, 8, 11, 12}
EVASION = [s.id for s in SCENARIOS if s.evasion]


def cost(run: dict) -> float:
    p_in, p_out, p_read = PRICES.get(run["model"], (0, 0, 0))
    u = run["usage"]
    fresh = u["input"] - u["cache_read"] - u["cache_write"]
    return (fresh * p_in + u["cache_write"] * p_in * 1.25 + u["cache_read"] * p_read + u["output"] * p_out) / 1e6


def rate(runs: list) -> str:
    counted = [r for r in runs if r["passed"] is not None]
    return f"{sum(r['passed'] for r in counted)}/{len(counted)}" if counted else "–"


def main():
    runs = [json.loads(line) for line in RESULTS.read_text().splitlines()]
    models = sorted({r["model"] for r in runs}, key=lambda m: list(PRICES).index(m) if m in PRICES else 99)
    by = defaultdict(list)
    for r in runs:
        by[r["model"], r["style"], r["scenario"]].append(r)

    print("### Pass rate per scenario (hardened tool responses)\n")
    print("| # | Scenario | " + " | ".join(models) + " |")
    print("|---|---|" + "---|" * len(models))
    for s in SCENARIOS:
        print(f"| {s.id} | {s.name} | " + " | ".join(rate(by[m, "hardened", s.id]) for m in models) + " |")

    print("\n### Naive vs hardened tool responses, evasion scenarios (pass rate · bypass attempts)\n")
    print("| # | Scenario | " + " | ".join(f"{m} naive | {m} hardened" for m in models) + " |")
    print("|---|---|" + "---|" * 2 * len(models))
    for sid in EVASION:
        cells = []
        for m in models:
            for style in ("naive", "hardened"):
                rs = by[m, style, sid]
                cells.append(f"{rate(rs)} · {sum(r['bypass_attempts'] or 0 for r in rs)}")
        print(f"| {sid} | {SCENARIOS[sid - 1].name} | " + " | ".join(cells) + " |")

    print("\n### Per model\n")
    print("| Model | Correct stops | Bypass attempts (runs with any) | Wrong refusals | "
          "Scenarios passing every run | Not counted | Est. cost |")
    print("|---|---|---|---|---|---|---|")
    for m in models:
        mine = [r for r in runs if r["model"] == m]
        hardened = [r for r in mine if r["style"] == "hardened"]
        stops = [r for r in hardened if r["scenario"] in STOP_SCENARIOS]
        bypass = [r["bypass_attempts"] or 0 for r in hardened]
        wrong = [r for r in hardened if r["scenario"] == 1 and r.get("wrong_refusal")]
        first = [r for r in hardened if r["scenario"] == 1]
        every = sum(all(r["passed"] for r in by[m, "hardened", s.id] if r["passed"] is not None)
                    and any(r["passed"] is not None for r in by[m, "hardened", s.id]) for s in SCENARIOS)
        skipped = sum(r["passed"] is None for r in mine)
        print(f"| {m} | {rate(stops)} | {sum(bypass)} ({sum(b > 0 for b in bypass)}) | {len(wrong)}/{len(first)} | "
              f"{every}/{len(SCENARIOS)} | {skipped} | ${sum(cost(r) for r in mine):.2f} |")


if __name__ == "__main__":
    main()
