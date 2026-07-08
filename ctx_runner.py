"""Part B: run each scenario through the vens CLI per model, parse the 4 OWASP
factors from the attestation, recompute the final risk (0-81) and OWASP band.

Keys + model via env. Usage:
  python3 ctx_runner.py --models gpt-5.4-mini --repeats 1        # validate
  python3 ctx_runner.py --models all --repeats 3                 # full
  python3 ctx_runner.py --models mock --repeats 1               # free plumbing test
"""
import argparse
import base64
import concurrent.futures as cf
import json
import os
import subprocess

VENS = "./vens"
SERIAL = "urn:uuid:00000000-0000-0000-0000-000000000001"

# name -> (llm backend, model env var, model id)
MODELS = {
    "gpt-5.4-nano":         ("openai", "OPENAI_MODEL", "gpt-5.4-nano"),
    "gpt-5.4-mini":         ("openai", "OPENAI_MODEL", "gpt-5.4-mini"),
    "gpt-5.5":              ("openai", "OPENAI_MODEL", "gpt-5.5"),
    "claude-haiku-4-5":     ("anthropic", "ANTHROPIC_MODEL", "claude-haiku-4-5"),
    "claude-sonnet-4-6":    ("anthropic", "ANTHROPIC_MODEL", "claude-sonnet-4-6"),
    "gemini-2.5-flash-lite":("googleai", "GOOGLE_MODEL", "gemini-2.5-flash-lite"),
    "gemini-2.5-flash":     ("googleai", "GOOGLE_MODEL", "gemini-2.5-flash"),
    "gemini-2.5-pro":       ("googleai", "GOOGLE_MODEL", "gemini-2.5-pro"),
    # local (Ollama) via vens --llm ollama (reads OLLAMA_MODEL, OLLAMA_HOST) -- free
    "llama3.2":             ("ollama", "OLLAMA_MODEL", "llama3.2"),
    "qwen2.5:7b":           ("ollama", "OLLAMA_MODEL", "qwen2.5:7b"),
    "gemma2:9b":            ("ollama", "OLLAMA_MODEL", "gemma2:9b"),
    "deepseek-r1:8b":       ("ollama", "OLLAMA_MODEL", "deepseek-r1:8b"),
    "mock":                 ("mock", "OPENAI_MODEL", "mock"),
}


def owasp_band(lik, impact):
    """Standard OWASP RR overall-risk matrix from Likelihood & Impact (0-9)."""
    def lvl(x):
        return 0 if x < 3 else (1 if x < 6 else 2)  # LOW/MED/HIGH
    matrix = [["Note", "Low", "Medium"],
              ["Low", "Medium", "High"],
              ["Medium", "High", "Critical"]]
    return matrix[lvl(impact)][lvl(lik)]


def parse_attestation(path):
    d = json.load(open(path))
    data = d["declarations"]["evidence"][0]["data"]
    fields = {}
    for item in data:
        c = item.get("contents", {}).get("attachment", {})
        val = c.get("content", "")
        if c.get("encoding") == "base64":
            val = base64.b64decode(val).decode()
        fields[item["name"]] = val
    raw = json.loads(fields["raw_response"])["results"][0]
    return raw, fields.get("model", "?")


def run_one(scenario, model, repeat):
    backend, env_var, model_id = MODELS[model]
    d = f"scenarios/{scenario}"
    os.makedirs("runs", exist_ok=True)
    out = f"runs/{scenario}__{model}__{repeat}.cdx.json"
    attest = out[:-len(".cdx.json")] + ".attestation.cdx.json"
    env = dict(os.environ, **{env_var: model_id})
    cmd = [VENS, "generate", "--llm", backend, "--config-file", f"{d}/config.yaml",
           "--llm-batch-size", "1", "--llm-temperature", "0", "--llm-seed", "7",
           "--attest", "--sbom-serial-number", SERIAL, f"{d}/report.json", out]

    def clear():  # never let a failed run re-parse a previous run's attestation
        for p in (out, attest):
            if os.path.exists(p):
                os.remove(p)

    clear()
    r = None
    for attempt in range(3):
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            r = None
        if r is not None and r.returncode == 0 and os.path.exists(attest):
            break
        clear()
    if r is None or r.returncode != 0 or not os.path.exists(attest):
        return {"scenario": scenario, "model": model, "repeat": repeat,
                "error": (r.stderr[-300:] if r is not None else "timeout/no-run")}
    raw, mid = parse_attestation(attest)
    ta, vu = raw["threat_agent_score"], raw["vulnerability_score"]
    ti, bi = raw["technical_impact"], raw["business_impact"]
    lik, impact = (ta + vu) / 2, (ti + bi) / 2
    risk = round(lik * impact, 1)
    return {"scenario": scenario, "model": model, "repeat": repeat, "model_id": mid,
            "threat_agent": ta, "vulnerability": vu, "technical_impact": ti,
            "business_impact": bi, "risk": risk, "band": owasp_band(lik, impact),
            "reasoning": raw.get("reasoning", "")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="mock")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--scenarios", default="all")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    names = [m for m in MODELS if m != "mock"] if args.models == "all" \
        else args.models.split(",")
    scenarios = list(json.load(open("scenarios/manifest.json")))
    if args.scenarios != "all":
        scenarios = args.scenarios.split(",")

    jobs = [(s, m, rp) for m in names for s in scenarios
            for rp in range(args.repeats)]
    os.makedirs("results", exist_ok=True)
    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(run_one, s, m, rp): (s, m, rp) for s, m, rp in jobs}
        for fut in cf.as_completed(futs):
            res = fut.result()
            results.append(res)
            tag = f"{res['scenario']}/{res['model']}"
            if "error" in res:
                print(f"  ERR  {tag}: {res['error'][:120]}")
            else:
                print(f"  ok   {tag:42s} risk={res['risk']:>4} {res['band']}")
    outpath = "results/context.json"
    existing = json.load(open(outpath)) if os.path.exists(outpath) else []
    k = lambda r: (r["scenario"], r["model"], r["repeat"])  # incremental merge
    fresh = {k(r) for r in results}
    merged = [r for r in existing if k(r) not in fresh] + results
    with open(outpath, "w") as f:
        json.dump(merged, f, indent=2)
    print(f"\nwrote {len(results)} new runs; {len(merged)} total in {outpath}")


if __name__ == "__main__":
    main()
