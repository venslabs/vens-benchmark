"""Part B analysis: showcases, directional families, repeat-consistency, and the
LLM-vs-baseline comparison. Reads results/context.json + results/baseline.json.
"""
import json
import os
import statistics as st
from collections import defaultdict, Counter


def load(path):
    return json.load(open(path)) if os.path.exists(path) else []


def group(runs):
    """(scenario, model) -> {factor: median, risk: median, risk_sd, band}"""
    by = defaultdict(list)
    for r in runs:
        if "error" not in r and r["model"] != "mock":
            by[(r["scenario"], r["model"])].append(r)
    agg = {}
    for key, rs in by.items():
        risks = [r["risk"] for r in rs]
        agg[key] = {
            "risk": st.median(risks),
            "risk_sd": round(st.stdev(risks), 1) if len(risks) > 1 else 0.0,
            "band": Counter(r["band"] for r in rs).most_common(1)[0][0],
            "vulnerability": st.median(r["vulnerability"] for r in rs),
            "threat_agent": st.median(r["threat_agent"] for r in rs),
            "technical_impact": st.median(r["technical_impact"] for r in rs),
            "business_impact": st.median(r["business_impact"] for r in rs),
            "reasoning": rs[0].get("reasoning", ""),
        }
    return agg


def main():
    ctx = group(load("results/context.json"))
    base = {r["scenario"]: r for r in load("results/baseline.json")}
    models = sorted({m for (_, m) in ctx})

    print("=== SHOWCASES (does the model modulate CVSS by context?) ===")
    print(f"{'model':22s} {'8.8 RCE -> expect LOW':>24s} {'5.3 leak -> expect HIGH':>26s}")
    for m in models:
        h = ctx.get(("showcase_high_to_low", m), {})
        l = ctx.get(("showcase_med_to_high", m), {})
        hp = "PASS" if h.get("band") in ("Note", "Low") else "fail"
        lp = "PASS" if l.get("band") in ("High", "Critical") else "fail"
        print(f"{m:22s} {h.get('risk','?'):>6}/{h.get('band','?'):9s}[{hp}] "
              f"{l.get('risk','?'):>6}/{l.get('band','?'):9s}[{lp}]")
    b = base.get("showcase_high_to_low", {})
    b2 = base.get("showcase_med_to_high", {})
    print(f"{'baseline (rules)':22s} {b.get('risk','?'):>6}/{b.get('band','?'):9s}"
          f"       {b2.get('risk','?'):>6}/{b2.get('band','?'):9s}")

    print("\n=== EXPOSURE family (threat_agent + risk should rise int<=priv<=net) ===")
    for m in models:
        vals = [(s, ctx.get((s, m), {}).get("risk", "?"),
                 ctx.get((s, m), {}).get("threat_agent", "?"))
                for s in ("expo_internal", "expo_private", "expo_internet")]
        mono = all(isinstance(vals[i][1], (int, float)) and vals[i][1] <= vals[i+1][1] + 0.01
                   for i in range(2))
        print(f"  {m:22s} risk {vals[0][1]}->{vals[1][1]}->{vals[2][1]}  "
              f"TA {vals[0][2]}->{vals[1][2]}->{vals[2][2]}  {'monotone' if mono else 'FLAT/wrong'}")

    print("\n=== CONTROLS family (vulnerability should drop off->on) ===")
    for m in models:
        off = ctx.get(("ctrl_off", m), {})
        on = ctx.get(("ctrl_on", m), {})
        ok = isinstance(on.get("vulnerability"), (int, float)) and \
            on["vulnerability"] <= off.get("vulnerability", 9) + 0.01
        print(f"  {m:22s} vuln {off.get('vulnerability','?')}->{on.get('vulnerability','?')}  "
              f"risk {off.get('risk','?')}->{on.get('risk','?')}  {'ok' if ok else 'no drop'}")

    print("\n=== CONSISTENCY (mean risk SD across 3 repeats; lower=better) ===")
    for m in models:
        sds = [v["risk_sd"] for (s, mm), v in ctx.items() if mm == m]
        print(f"  {m:22s} mean risk SD = {round(st.mean(sds), 2) if sds else '?'}")

    print("\n=== WRONG-YAML (context lies 'internal/low'; real CVE = payment auth-bypass) ===")
    print("  high risk = model overrides wrong context; low = blindly follows it")
    for m in models:
        w = ctx.get(("wrong_yaml", m), {})
        print(f"  {m:22s} risk={w.get('risk','?')}/{w.get('band','?')}")
    print(f"  baseline (rules)       risk={base.get('wrong_yaml',{}).get('risk','?')}"
          f"/{base.get('wrong_yaml',{}).get('band','?')}  (follows context by construction)")

    def ladder(title, ids, factor):
        print(f"\n=== {title} ===")
        for m in models:
            vals = [ctx.get((s, m), {}).get(factor, "?") for s in ids]
            risks = [ctx.get((s, m), {}).get("risk", "?") for s in ids]
            ok = all(isinstance(vals[i], (int, float)) and isinstance(vals[i + 1], (int, float))
                     and vals[i] <= vals[i + 1] + 0.01 for i in range(len(vals) - 1))
            print(f"  {m:22s} {factor} {'->'.join(str(v) for v in vals)}  "
                  f"risk {'->'.join(str(r) for r in risks)}  {'monotone' if ok else 'FLAT/wrong'}")

    ladder("DATA_SENSITIVITY ladder (technical_impact should rise low<=high<=critical)",
           ("sens_low", "sens_high", "sens_critical"), "technical_impact")
    ladder("BUSINESS_CRITICALITY (business_impact should rise low<=critical)",
           ("crit_low", "crit_critical"), "business_impact")
    ladder("COMPLIANCE (business_impact should rise none<=gdpr)",
           ("comp_none", "comp_gdpr"), "business_impact")

    print("\n=== DISCRIMINATORS (LLM must READ the CVE to apply context correctly) ===")
    bdos = base.get("disc_dos", {})
    print(f"  [DoS + critical data] naive rule technical={bdos.get('technical_impact','?')} "
          f"risk={bdos.get('risk','?')} -- a reading model should score technical LOWER")
    for m in models:
        d = ctx.get(("disc_dos", m), {})
        good = isinstance(d.get("technical_impact"), (int, float)) and d["technical_impact"] < bdos.get("technical_impact", 9)
        print(f"    {m:22s} technical={d.get('technical_impact','?')} risk={d.get('risk','?')}  {'reads DoS' if good else '= naive'}")
    baud = base.get("disc_audit", {})
    print(f"\n  [accountability + low data] naive rule technical={baud.get('technical_impact','?')} "
          f"risk={baud.get('risk','?')} -- a reading model should score technical HIGHER (audit_req)")
    for m in models:
        d = ctx.get(("disc_audit", m), {})
        good = isinstance(d.get("technical_impact"), (int, float)) and d["technical_impact"] > baud.get("technical_impact", 0)
        print(f"    {m:22s} technical={d.get('technical_impact','?')} risk={d.get('risk','?')}  {'uses audit_req' if good else '= naive'}")
    print(f"\n  [reachability via notes] naive rule reach_yes=reach_no="
          f"{base.get('reach_yes',{}).get('risk','?')} (ignores notes) -- a reading model should differ")
    for m in models:
        y = ctx.get(("reach_yes", m), {}).get("risk", "?")
        n = ctx.get(("reach_no", m), {}).get("risk", "?")
        moved = isinstance(y, (int, float)) and isinstance(n, (int, float)) and y - n > 0.5
        print(f"    {m:22s} reachable={y} unreachable={n}  {'moved ' + str(round(y - n, 1)) if moved else 'FLAT (ignored notes)'}")
    print("\n  [relevant vs irrelevant control] vulnerability under a WAF")
    for m in models:
        r_off = ctx.get(("ctrl_off", m), {}).get("vulnerability", "?")
        r_on = ctx.get(("ctrl_on", m), {}).get("vulnerability", "?")
        irr = ctx.get(("disc_ctrl_irrelevant", m), {}).get("vulnerability", "?")
        print(f"    {m:22s} web-RCE+WAF {r_off}->{r_on} (should drop) | local-bug+WAF vuln={irr} (should NOT drop)")

    print("\n=== TELEGRAPHED vs NON-TELEGRAPHED (construct validity) ===")
    print("  same context; the nt CVE no longer names the impact class. A model that")
    print("  reasons keeps its factor; one that keyword-matched drifts back toward naive.")

    def famrows(factor, tel, nt):
        for m in models:
            tv = [ctx[(s, m)][factor] for s in tel if (s, m) in ctx]
            nv = [ctx[(s, m)][factor] for s in nt if (s, m) in ctx]
            tm = round(st.mean(tv), 1) if tv else "?"
            nm = round(st.mean(nv), 1) if nv else "?"
            drift = f"{nm - tm:+.1f}" if tv and nv else "?"
            print(f"    {m:22s} telegraphed={tm:>4}  non-telegraphed={nm:>4}  drift={drift:>5}")

    print("\n  DoS technical_impact (naive rule=9; a reading model scores LOWER and should")
    print("       NOT drift back up once 'denial of service' is removed):")
    famrows("technical_impact", ["disc_dos", "disc_dos2", "disc_dos3"],
            ["disc_dos_nt", "disc_dos_nt2"])
    print("\n  Accountability technical_impact (naive rule=2; a reading model scores HIGHER")
    print("       via audit_requirement and should stay high without the word 'audit'):")
    famrows("technical_impact", ["disc_audit", "disc_audit2", "disc_audit3"],
            ["disc_audit_nt", "disc_audit_nt2"])
    print("\n  Irrelevant WAF: vulnerability on the local bug. no-WAF is the SAME local bug")
    print("       without controls; a WAF at the edge must not lower a local-file exploit:")
    for m in models:
        off = ctx.get(("disc_ctrl_off_local", m), {}).get("vulnerability", "?")
        tel = ctx.get(("disc_ctrl_irrelevant", m), {}).get("vulnerability", "?")
        nt = ctx.get(("disc_ctrl_irrelevant_nt", m), {}).get("vulnerability", "?")
        print(f"    {m:22s} no-WAF={off}  WAF(telegraphed)={tel}  WAF(non-telegraphed)={nt}")

    print("\n=== LLM vs BASELINE (risk per scenario; divergence = LLM adds value) ===")
    scen = sorted({s for (s, _) in ctx})
    print(f"{'scenario':24s} {'baseline':>9s} " + " ".join(f"{m[:10]:>10s}" for m in models))
    for s in scen:
        row = f"{s:24s} {base.get(s,{}).get('risk','?'):>9} "
        row += " ".join(f"{ctx.get((s,m),{}).get('risk','?'):>10}" for m in models)
        print(row)


if __name__ == "__main__":
    main()
