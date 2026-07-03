# vens-benchmark

Benchmarking LLMs for context-aware CVE risk scoring, for [vens](https://github.com/venslabs/vens).

Two halves, because "best model for vens" needs both:

1. **CVE understanding** (which model reads a CVE best) — reuses the public
   **CTIBench / CTI-VSP** task (predict the CVSS v3.1 vector from the
   description), metric = **MAD** (mean absolute error on the base score). We add
   the 2026 models CTIBench never tested and place them against its published
   baselines and against a non-LLM floor.
2. **Context modulation** (which model uses the project context best) — vens's
   own contribution, since no public dataset labels risk conditioned on
   exposure / sensitivity / criticality / controls / compliance. Contrastive /
   metamorphic scenarios (vary one context axis, known expected direction) run
   through the vens CLI, plus the 2 showcase cases and "wrong-YAML" controls.

Every model is compared against a **non-LLM baseline** (a rule mapper + a
constant predictor): the LLM must beat it to justify its cost.

Reported as a **Pareto front** (quality × cost × latency × failure-rate) with
confidence intervals — not a single scalar ranking.

## Data & license

- Code and the vens context dataset: Apache-2.0.
- **CTIBench data is CC BY-NC-SA 4.0 (NonCommercial) and is NOT redistributed
  here.** Download it at runtime (derived from NVD, public domain):

  ```
  gh api repos/xashru/cti-bench/contents/data/cti-vsp.tsv \
    -H "Accept: application/vnd.github.raw" > data/cti-vsp.tsv
  ```

  Attribution: CTIBench — https://github.com/xashru/cti-bench (NeurIPS 2024).

API keys are read from the environment and never committed.
