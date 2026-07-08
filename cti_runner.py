"""Run the CTIBench CTI-VSP task across providers and compute MAD vs NVD CVSS.

Keys are read from env: OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_API_KEY.
Never hardcode keys. Raw outputs saved under results/ (gitignored).

Usage:
  python3 cti_runner.py --models gemini-2.5-flash-lite --limit 1        # free validate
  python3 cti_runner.py --models all --limit 200                        # full run
  python3 cti_runner.py --models gpt-5.5 --limit 200 --effort minimal   # bridle
"""
import argparse
import csv
import json
import os
import re
import statistics
import sys
import time

from cvss import CVSS3

# provider, api model id, is-reasoning (OpenAI gpt-5.x reject temperature),
# price $/1M (in, out) for cost tracking.
MODELS = {
    "gpt-5.4-nano":         ("openai", "gpt-5.4-nano", True,  (0.20, 1.25)),
    "gpt-5.4-mini":         ("openai", "gpt-5.4-mini", True,  (0.75, 4.50)),
    "gpt-5.5":              ("openai", "gpt-5.5",      True,  (5.00, 30.0)),
    "claude-haiku-4-5":     ("anthropic", "claude-haiku-4-5",  False, (1.00, 5.00)),
    "claude-sonnet-4-6":    ("anthropic", "claude-sonnet-4-6", False, (3.00, 15.0)),
    "gemini-2.5-flash-lite":("google", "gemini-2.5-flash-lite", False, (0.10, 0.40)),
    "gemini-2.5-flash":     ("google", "gemini-2.5-flash",      False, (0.30, 2.50)),
    "gemini-2.5-pro":       ("google", "gemini-2.5-pro",        False, (1.25, 10.0)),
    # local (Ollama) -- free ($0); run explicitly, not via --models all + cloud
    "llama3.2":             ("ollama", "llama3.2",       False, (0.0, 0.0)),
    "qwen2.5:7b":           ("ollama", "qwen2.5:7b",     False, (0.0, 0.0)),
    "gemma2:9b":            ("ollama", "gemma2:9b",      False, (0.0, 0.0)),
    "deepseek-r1:8b":       ("ollama", "deepseek-r1:8b", False, (0.0, 0.0)),
}

VEC_RE = re.compile(r"CVSS:3\.[01]/[A-Z:/.]+")


def base_score(vector):
    try:
        return float(CVSS3(vector.strip().rstrip("/")).base_score)
    except Exception:
        return None


def extract_score(text):
    """Pull the CVSS vector from the model's free-text answer -> base score."""
    m = VEC_RE.findall(text or "")
    for v in reversed(m):  # last vector is usually the final answer
        s = base_score(v)
        if s is not None:
            return s, v
    return None, None


def call_openai(model, prompt, effort):
    from openai import OpenAI
    cli = OpenAI(base_url=os.getenv("OPENAI_BASE_URL") or None)
    r = cli.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        reasoning_effort=effort,  # gpt-5.x reject temperature; steer with effort
    )
    u = r.usage
    return r.choices[0].message.content or "", (u.prompt_tokens, u.completion_tokens)


def call_anthropic(model, prompt):
    import anthropic
    cli = anthropic.Anthropic()
    r = cli.messages.create(
        model=model, max_tokens=1024, temperature=0,
        messages=[{"role": "user", "content": prompt}],
    )
    txt = "".join(b.text for b in r.content if b.type == "text")
    return txt, (r.usage.input_tokens, r.usage.output_tokens)


def call_google(model, prompt):
    from google import genai
    from google.genai import types
    cli = genai.Client()
    r = cli.models.generate_content(
        model=model, contents=prompt,
        config=types.GenerateContentConfig(temperature=0),
    )
    um = r.usage_metadata
    return (r.text or ""), (um.prompt_token_count, um.candidates_token_count or 0)


def call_ollama(model, prompt):
    """Local model via Ollama's OpenAI-compatible endpoint (free, no key)."""
    from openai import OpenAI
    cli = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    r = cli.chat.completions.create(
        model=model, temperature=0, max_tokens=4096,  # room for reasoning models
        messages=[{"role": "user", "content": prompt}],
    )
    u = r.usage
    return r.choices[0].message.content or "", (u.prompt_tokens or 0, u.completion_tokens or 0)


def _one(provider, mid, effort, r):
    """Score one CVE with retries. Returns (pred, gt, tokens_in, tokens_out)."""
    prompt = f"{r['Prompt']}\n\nCVE description:\n{r['Description']}"
    for attempt in range(5):
        try:
            if provider == "openai":
                txt, (ci, co) = call_openai(mid, prompt, effort)
            elif provider == "anthropic":
                txt, (ci, co) = call_anthropic(mid, prompt)
            elif provider == "ollama":
                txt, (ci, co) = call_ollama(mid, prompt)
            else:
                txt, (ci, co) = call_google(mid, prompt)
            pred, _vec = extract_score(txt)
            return r["URL"], pred, base_score(r["GT"]), ci, co
        except Exception as e:
            if attempt == 4:
                print(f"  [{mid}] ERROR after retries: {e}", file=sys.stderr)
                return r["URL"], None, base_score(r["GT"]), 0, 0
            time.sleep(min(2 ** attempt * 2, 30))


def run_model(name, rows, effort, workers=6):
    from concurrent.futures import ThreadPoolExecutor
    provider, mid, _reason, (pin, pout) = MODELS[name]
    if provider == "ollama":
        workers = 2  # local GPU serializes; more workers just thrash memory
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        out = list(ex.map(lambda r: _one(provider, mid, effort, r), rows))
    preds = [p for _, p, g, _, _ in out if p is not None]
    gts = [g for _, p, g, _, _ in out if p is not None]
    fails = sum(1 for _, p, _, _, _ in out if p is None)
    tin = sum(ci for _, _, _, ci, _ in out)
    tout = sum(co for _, _, _, _, co in out)
    mad = statistics.mean(abs(p - g) for p, g in zip(preds, gts)) if preds else None
    with open(f"results/preds_{name}.json", "w") as f:  # per-CVE for CIs + failure catalog
        json.dump([{"url": u, "pred": p, "gt": g} for u, p, g, _, _ in out], f)
    cost = (tin * pin + tout * pout) / 1e6
    return {
        "model": name, "id": mid, "n": len(rows), "parsed": len(preds),
        "parse_fail": fails, "mad": mad,
        "tokens_in": tin, "tokens_out": tout, "cost_usd": round(cost, 4),
        "latency_s": round(time.time() - t0, 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="gemini-2.5-flash-lite")
    ap.add_argument("--limit", type=int, default=1)
    ap.add_argument("--effort", default="low")  # openai reasoning_effort
    ap.add_argument("--data", default="data/cti-vsp.tsv")
    args = ap.parse_args()

    names = list(MODELS) if args.models == "all" else args.models.split(",")
    with open(args.data, newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))[: args.limit]

    os.makedirs("results", exist_ok=True)
    outpath = "results/ctibench.json"
    merged = {}
    if os.path.exists(outpath):  # incremental: keep results from prior runs
        for r in json.load(open(outpath)):
            merged[r["model"]] = r
    for name in names:
        print(f"== {name} ({args.limit} CVEs) ==", file=sys.stderr)
        res = run_model(name, rows, args.effort)
        merged[name] = res
        print(json.dumps(res))
    out = list(merged.values())
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    print("\n=== SUMMARY (lower MAD = better; floor 'always 7.5' = 1.573 on 200) ===")
    for r in sorted(out, key=lambda x: (x["mad"] is None, x["mad"] or 9)):
        print(f"  {r['model']:24s} MAD={r['mad']} parsed={r['parsed']}/{r['n']} "
              f"fails={r['parse_fail']} cost=${r['cost_usd']} {r['latency_s']}s")


if __name__ == "__main__":
    main()
