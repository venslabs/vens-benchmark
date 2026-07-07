"""Non-LLM baseline: the 'dumb rule engine' the LLM must beat.

Replicates vens's prompt arithmetic in code (technical = data_sensitivity,
business = criticality + compliance, threat = exposure band) and copies the
vendor Severity label for the vulnerability factor -- because a rule engine
CANNOT judge exploitability from the CVE. Divergence between the LLM and this
baseline is exactly where the LLM earns its cost (the `vulnerability` factor +
context edge cases like unreachability).
"""
import json
import glob
import os

import yaml

LEVEL = {"low": 2, "medium": 5, "high": 7, "critical": 9}
EXPOSURE = {"internal": 2, "private": 4, "internet": 8}
SEVERITY = {"LOW": 3, "MEDIUM": 5, "HIGH": 7, "CRITICAL": 8}


def owasp_band(lik, impact):
    def lvl(x):
        return 0 if x < 3 else (1 if x < 6 else 2)
    matrix = [["Note", "Low", "Medium"], ["Low", "Medium", "High"],
              ["Medium", "High", "Critical"]]
    return matrix[lvl(impact)][lvl(lik)]


def score(cfg, report):
    ctx = cfg["context"]
    sev = report["Results"][0]["Vulnerabilities"][0]["Severity"]
    ta = EXPOSURE.get(ctx.get("exposure", "private"), 4)
    vu = SEVERITY.get(sev, 5)                 # copy vendor severity (no reasoning)
    ti = LEVEL.get(ctx.get("data_sensitivity", "medium"), 5)
    bi = LEVEL.get(ctx.get("business_criticality", "medium"), 5)
    if ctx.get("compliance_requirements"):
        bi = min(9, bi + 2)
    lik, impact = (ta + vu) / 2, (ti + bi) / 2
    return {"threat_agent": ta, "vulnerability": vu, "technical_impact": ti,
            "business_impact": bi, "risk": round(lik * impact, 1),
            "band": owasp_band(lik, impact)}


def main():
    out = []
    for d in sorted(glob.glob("scenarios/*/")):
        sid = os.path.basename(d.rstrip("/"))
        cfg = yaml.safe_load(open(f"{d}/config.yaml"))
        report = json.load(open(f"{d}/report.json"))
        s = score(cfg, report)
        s.update(scenario=sid, model="baseline", repeat=0, reasoning="rule engine")
        out.append(s)
        print(f"  {sid:24s} risk={s['risk']:>5} {s['band']}")
    with open("results/baseline.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {len(out)} baseline scores to results/baseline.json")


if __name__ == "__main__":
    main()
