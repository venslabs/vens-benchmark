"""Extra rigor for the paper, computed from existing data (no API calls):

1. Baseline threshold sensitivity -- recompute the rule engine under 3 different
   numeric threshold sets and show the discriminator conclusions do not flip
   (they rest on the rule's structural blindness, not the exact numbers).
2. Significance -- Wilcoxon signed-rank of per-scenario (LLM - baseline) risk,
   per model, plus a binomial sign test on each discriminator across CVEs x models.
"""
import glob
import json
import os
import statistics as st
from collections import defaultdict

import yaml

try:
    from scipy.stats import wilcoxon, binomtest
    HAVE_SCIPY = True
except ImportError:
    HAVE_SCIPY = False

# threshold variants: (LEVEL, EXPOSURE, SEVERITY)
VARIANTS = {
    "default":    ({"low":2,"medium":5,"high":7,"critical":9},
                   {"internal":2,"private":4,"internet":8},
                   {"LOW":3,"MEDIUM":5,"HIGH":7,"CRITICAL":8}),
    "compressed": ({"low":3,"medium":5,"high":6,"critical":8},
                   {"internal":3,"private":5,"internet":7},
                   {"LOW":4,"MEDIUM":5,"HIGH":6,"CRITICAL":8}),
    "spread":     ({"low":1,"medium":4,"high":7,"critical":9},
                   {"internal":1,"private":4,"internet":9},
                   {"LOW":2,"MEDIUM":5,"HIGH":7,"CRITICAL":9}),
}


def baseline_score(cfg, report, LEVEL, EXPOSURE, SEVERITY):
    ctx = cfg["context"]
    sev = report["Results"][0]["Vulnerabilities"][0]["Severity"]
    ta = EXPOSURE.get(ctx.get("exposure","private"), 4)
    vu = SEVERITY.get(sev, 5)
    ti = LEVEL.get(ctx.get("data_sensitivity","medium"), 5)
    bi = LEVEL.get(ctx.get("business_criticality","medium"), 5)
    if ctx.get("compliance_requirements"):
        bi = min(9, bi + 2)
    return {"technical": ti, "risk": round(((ta+vu)/2)*((ti+bi)/2), 1)}


def load_scenarios():
    out = {}
    for d in sorted(glob.glob("scenarios/*/")):
        sid = os.path.basename(d.rstrip("/"))
        out[sid] = (yaml.safe_load(open(f"{d}/config.yaml")),
                    json.load(open(f"{d}/report.json")))
    return out


def group_llm():
    by = defaultdict(list)
    for r in json.load(open("results/context.json")):
        if "error" not in r and r["model"] != "mock":
            by[(r["scenario"], r["model"])].append(r)
    agg = {}
    for key, rs in by.items():
        agg[key] = {"risk": st.median(r["risk"] for r in rs),
                    "technical": st.median(r["technical_impact"] for r in rs)}
    return agg


def main():
    scen = load_scenarios()
    llm = group_llm()
    models = sorted({m for (_, m) in llm})

    print("=== 1. BASELINE THRESHOLD SENSITIVITY ===")
    print("   do the discriminator conclusions survive 3 different threshold sets?")
    # n=5 per family: 3 telegraphed + 2 non-telegraphed CVEs (effect size, not a clean p)
    audit_ids = ["disc_audit","disc_audit2","disc_audit3","disc_audit_nt","disc_audit_nt2"]
    dos_ids = ["disc_dos","disc_dos2","disc_dos3","disc_dos_nt","disc_dos_nt2"]
    for vname,(L,E,S) in VARIANTS.items():
        base = {sid: baseline_score(c, r, L, E, S) for sid,(c,r) in scen.items()}
        audit_ok = all(llm.get((s,m),{}).get("technical",0) > base[s]["technical"]
                       for s in audit_ids for m in models if (s,m) in llm)
        dos_ok = all(llm.get((s,m),{}).get("technical",9) < base[s]["technical"]
                     for s in dos_ids for m in models if (s,m) in llm)
        reach_flat = all(base[f"reach{n}_yes" if n else "reach_yes"]["risk"]
                         == base[f"reach{n}_no" if n else "reach_no"]["risk"]
                         for n in ("","2","3"))
        print(f"   [{vname:10s}] audit LLM>rule: {audit_ok} | dos LLM<=rule: {dos_ok} "
              f"| reach rule-flat: {reach_flat}")

    print("\n=== 2. SIGNIFICANCE ===")
    L,E,S = VARIANTS["default"]
    base = {sid: baseline_score(c, r, L, E, S) for sid,(c,r) in scen.items()}
    print("   Wilcoxon signed-rank: per-scenario (LLM risk - baseline risk), per model")
    for m in models:
        diffs = [llm[(s,m)]["risk"] - base[s]["risk"] for s in scen if (s,m) in llm]
        nz = [d for d in diffs if d != 0]
        if HAVE_SCIPY and len(nz) >= 6:
            w = wilcoxon(nz)  # normal approx (ties); nz excludes zero-diffs
            print(f"   {m:22s} n={len(diffs)} nz={len(nz)} median_diff={st.median(diffs):+.1f} "
                  f"W={w.statistic:.0f} p={w.pvalue:.4f} {'*' if w.pvalue < 0.05 else 'ns'}")
        else:
            pos = sum(1 for d in nz if d > 0)
            print(f"   {m:22s} n={len(diffs)} median_diff={st.median(diffs):+.1f} "
                  f"pos/neg={pos}/{len(nz)-pos}")

    print("\n   Discriminator sign tests (pooled CVEs x models):")
    def signtest(name, ids, cmp):
        trials = [(s,m) for s in ids for m in models if (s,m) in llm]
        wins = sum(1 for (s,m) in trials if cmp(llm[(s,m)], base[s]))
        p = binomtest(wins, len(trials), 0.5, "greater").pvalue if HAVE_SCIPY and trials else None
        print(f"     {name:34s} {wins}/{len(trials)}" + (f"  p={p:.4f}" if p is not None else ""))
    signtest("audit: LLM technical > rule", audit_ids, lambda a,b: a["technical"] > b["technical"])
    signtest("DoS: LLM technical < rule", dos_ids, lambda a,b: a["technical"] < b["technical"])
    pairs = [("reach_yes","reach_no"),("reach2_yes","reach2_no"),("reach3_yes","reach3_no")]
    trials = [(p,m) for p in pairs for m in models if (p[0],m) in llm and (p[1],m) in llm]
    wins = sum(1 for ((y,n),m) in trials if llm[(y,m)]["risk"] - llm[(n,m)]["risk"] > 0.5)
    p = binomtest(wins, len(trials), 0.5, "greater").pvalue if HAVE_SCIPY and trials else None
    print(f"     {'reachability: LLM moves (rule flat)':34s} {wins}/{len(trials)}" +
          (f"  p={p:.4f}" if p is not None else ""))


if __name__ == "__main__":
    main()
