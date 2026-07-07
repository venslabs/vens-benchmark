"""Analyze CTIBench results: ranking, Pareto front, bootstrap CIs, bias, and the
failure catalog. Reads results/ctibench.json (aggregates) + results/preds_*.json
(per-CVE, where captured). Honest stats: CIs, not bare point estimates.
"""
import glob
import json
import os
import random
import statistics

random.seed(7)  # reproducible bootstrap
FLOOR = 1.573   # "always predict 7.5", computed on the same rows[:200] the models use
                # (1.538 was on all 1000 rows -- a sample mismatch)
PUBLISHED = {"Gemini-1.5 (2024)": 1.09, "GPT-4 (2024)": 1.31,
             "GPT-3.5 (2024)": 1.57, "Llama3-70B (2024)": 1.83}


def load_summaries():
    with open("results/ctibench.json") as f:
        return json.load(f)


def load_preds(model):
    p = f"results/preds_{model}.json"
    if not os.path.exists(p):
        return None
    rows = json.load(open(p))
    return [(r["pred"], r["gt"]) for r in rows if r["pred"] is not None]


def bootstrap_mad_ci(errs, iters=4000):
    n = len(errs)
    means = []
    for _ in range(iters):
        s = [errs[random.randrange(n)] for _ in range(n)]
        means.append(sum(s) / n)
    means.sort()
    return means[int(0.025 * iters)], means[int(0.975 * iters)]


def pareto_front(models):
    """Non-dominated on (mad down, cost down)."""
    front = []
    for m in models:
        if m["mad"] is None:
            continue
        dominated = any(
            o["mad"] is not None and o is not m
            and o["mad"] <= m["mad"] and o["cost_usd"] <= m["cost_usd"]
            and (o["mad"] < m["mad"] or o["cost_usd"] < m["cost_usd"])
            for o in models
        )
        if not dominated:
            front.append(m["model"])
    return front


def main():
    models = [m for m in load_summaries() if m["mad"] is not None]
    models.sort(key=lambda m: m["mad"])
    front = set(pareto_front(models))

    print("=== RANKING (MAD lower=better; floor=1.538; GPT-4'24=1.31) ===")
    print(f"{'model':22s} {'MAD':>6s} {'95% CI':>16s} {'bias':>7s} "
          f"{'$/200':>7s} {'pareto':>7s}")
    for m in models:
        preds = load_preds(m["model"])
        if preds:
            errs = [abs(p - g) for p, g in preds]
            lo, hi = bootstrap_mad_ci(errs)
            ci = f"[{lo:.2f},{hi:.2f}]"
            bias = statistics.mean(p - g for p, g in preds)  # + = over-rates
            biass = f"{bias:+.2f}"
        else:
            ci, biass = "(aggregate)", "n/a"
        star = "  ***" if m["model"] in front else ""
        print(f"{m['model']:22s} {m['mad']:6.3f} {ci:>16s} {biass:>7s} "
              f"${m['cost_usd']:6.2f}{star}")

    print(f"\nPareto-optimal (best MAD for the cost): {', '.join(sorted(front))}")

    print("\n=== vs published baselines ===")
    best = models[0]
    for name, mad in sorted(PUBLISHED.items(), key=lambda x: x[1]):
        print(f"  {name:20s} {mad}")
    print(f"  -> best 2026 model ({best['model']}) = {best['mad']:.3f}")

    # Failure catalog from the strongest model that has per-CVE data.
    ref = next((m["model"] for m in models if load_preds(m["model"])), None)
    if ref:
        rows = json.load(open(f"results/preds_{ref}.json"))
        rows = [r for r in rows if r["pred"] is not None]
        for r in rows:
            r["err"] = r["pred"] - r["gt"]
        worst = sorted(rows, key=lambda r: -abs(r["err"]))[:10]
        over = sum(1 for r in rows if r["err"] > 1)
        under = sum(1 for r in rows if r["err"] < -1)
        print(f"\n=== FAILURE CATALOG (ref model: {ref}) ===")
        print(f"  over-rates (>+1): {over}/{len(rows)}  "
              f"under-rates (<-1): {under}/{len(rows)}")
        for r in worst:
            print(f"  err={r['err']:+.1f}  pred={r['pred']} gt={r['gt']}  "
                  f"{r['url'].split('/')[-1]}")


if __name__ == "__main__":
    main()
