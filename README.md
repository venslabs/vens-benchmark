# vens-benchmark

Which LLM should you run [vens](https://github.com/venslabs/vens) with? This benchmarks models on the job vens actually does: scoring a CVE's risk from a scanner report plus project context.

**Paper:** [Which LLM Should Score Your CVEs?](paper/vens-benchmark.pdf) — methodology, all 12 models, and where it fails.

## Which model to pick

200 CVEs, CTIBench CVSS task, July 2026. MAD = mean absolute error vs the NVD base score (lower is better).

| Model | MAD | $/200 | Note |
|---|---|---|---|
| claude-sonnet-4-6 | 0.75 | $1.88 | most accurate, stable — default for signed VEX |
| gpt-5.5 | 0.75 | $4.12 | same accuracy as sonnet, 2× the price — skip |
| gpt-5.4-mini | 0.84 | $0.48 | best value; jittery, run n≥3 |
| gemini-2.5-pro | 0.88 | $1.16 | solid middle |
| gemini-2.5-flash-lite | 1.15 | $0.07 | cheapest; over-rates and adds little on context |
| claude-haiku-4-5 | 1.29 | $0.52 | below the value line |

A constant "always 7.5" guess scores 1.57. A model above that isn't worth the call.

**Short version:** sonnet if you sign or audit the output, gpt-5.4-mini for cheap-and-good, flash-lite for throwaway triage. Don't pay for gpt-5.5.

Context sensitivity, the two showcases (Log4Shell 10.0 → LOW, an axios leak 5.3 → HIGH), and where models fail are in `report.html`.

## Benchmark your own model

```
git clone https://github.com/venslabs/vens-benchmark && cd vens-benchmark
pip install -r requirements.txt
export OPENAI_API_KEY=...          # and/or ANTHROPIC_API_KEY, GOOGLE_API_KEY

python3 cti_runner.py --models <name> --limit 200    # Half A: accuracy (MAD vs NVD)
python3 baseline.py                                   # the non-LLM baseline to beat
python3 ctx_runner.py --models <name> --repeats 3     # Half B: context (needs the vens binary)
python3 cti_analyze.py && python3 ctx_analyze.py      # ranking, Pareto front, failure catalog
```

Add a model in one line in the `MODELS` dict (`cti_runner.py` / `ctx_runner.py`). Local models run through [Ollama](https://ollama.com) with no key and no cost, e.g. `--models qwen2.5:7b`.

Half B calls the real `vens generate` CLI, so drop the `vens` binary in this directory (or `go build` it from the [vens repo](https://github.com/venslabs/vens)).

## What the two halves measure

- **Half A** — predict the CVSS v3.1 vector from the CVE text (the public CTIBench task), scored by MAD against NVD. Raw CVE understanding.
- **Half B** — run 35 project-context scenarios through vens and check the OWASP risk moves the right way when you change exposure, data sensitivity, criticality, reachability, or controls. Every model is measured against a non-LLM rule engine it has to beat.

## Data & license

- Code and the vens context scenarios: Apache-2.0.
- **CTIBench data is CC BY-NC-SA 4.0 (NonCommercial) and is not shipped here.** Fetch it at runtime (it derives from NVD, public domain):

  ```
  gh api repos/xashru/cti-bench/contents/data/cti-vsp.tsv \
    -H "Accept: application/vnd.github.raw" > data/cti-vsp.tsv
  ```

  Attribution: CTIBench — https://github.com/xashru/cti-bench (NeurIPS 2024).

API keys are read from the environment, never committed.
