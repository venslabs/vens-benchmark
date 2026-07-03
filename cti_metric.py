"""CTIBench CTI-VSP metric pipeline (MAD on CVSS v3.1 base score).

Free validation: parse ground-truth vectors -> base scores, compute the MAD of
non-LLM baselines (constant / median predictor) as a floor any model must beat,
and report the GT distribution to size the sample.
"""
import csv
import statistics
import sys

try:
    from cvss import CVSS3
except ImportError:
    print("pip install cvss", file=sys.stderr)
    raise


def base_score(vector: str):
    try:
        return float(CVSS3(vector.strip()).base_score)
    except Exception:
        return None


def load(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    return rows


def mad(preds, gts):
    diffs = [abs(p - g) for p, g in zip(preds, gts) if p is not None and g is not None]
    return sum(diffs) / len(diffs) if diffs else None


def main(path):
    rows = load(path)
    gts = [base_score(r["GT"]) for r in rows]
    gts = [g for g in gts if g is not None]
    n = len(gts)
    med = statistics.median(gts)
    mean = statistics.mean(gts)

    print(f"parsed GT scores: {n}/{len(rows)}")
    print(f"GT base score: mean={mean:.2f} median={med:.2f} "
          f"min={min(gts)} max={max(gts)} sd={statistics.pstdev(gts):.2f}")

    # Non-LLM baselines (the floor an LLM must beat) on the full GT set.
    for name, const in [("predict-median", med), ("predict-mean", round(mean, 1)),
                        ("predict-7.5(High)", 7.5), ("predict-5.0", 5.0)]:
        print(f"  baseline {name:20s} MAD={mad([const]*n, gts):.3f}")

    # CTIBench published baselines (from the paper, for reference):
    print("  published (CTIBench paper): Gemini-1.5=1.09  GPT-4=1.31  "
          "GPT-3.5=1.57  Llama3-70B=1.83  Llama3-8B=1.91")

    # Sample-size intuition: SE of MAD ~ sd(|err|)/sqrt(k). For a tight CI on a
    # model's MAD, ~150-200 items gives SE ~ 0.06-0.08.
    print("sample sizing: 150-200 CVEs -> MAD SE ~0.06-0.08 (tight enough to "
          "separate models >~0.2 apart, e.g. Gemini-1.5 1.09 vs GPT-3.5 1.57)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/cti-vsp.tsv")
