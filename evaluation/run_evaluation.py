"""APIGuard detection-accuracy evaluation.

Scans all four benchmark targets through the running APIGuard backend, compares
every verdict with the source-code-derived ground truth in ground_truth.yaml and
reports TP / FP / TN / FN, precision, recall, F1 and accuracy.

Prerequisite: start everything first (scripts/run_all.ps1 or scripts/run_all.sh).
Run from the project root:

    python evaluation/run_evaluation.py

Outputs evaluation/results/evaluation_report.md and evaluation_results.json.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml

HERE = Path(__file__).resolve().parent
CATEGORIES = ["authentication", "authorization", "input_validation", "data_exposure"]
CATEGORY_OF = {"AUTH": "authentication", "AUTHZ": "authorization", "INPUT": "input_validation", "DATA": "data_exposure"}
TARGETS = [
    ("target-vulnerable-demo", "APIGuard demo API - vulnerable", "own"),
    ("target-secure-demo", "APIGuard demo API - secure", "own"),
    ("target-vampi-vulnerable", "VAmPI - vulnerable", "third-party"),
    ("target-vampi-secure", "VAmPI - secure mode", "third-party"),
]
FLAGGED = {"CONFIRMED", "SUSPECTED"}


def run_scan(client: httpx.Client, base: str, target_id: str) -> tuple[dict, list[dict]]:
    resp = client.post(f"{base}/api/scans", json={"target_id": target_id, "categories": CATEGORIES, "auth_profile": "alice"})
    resp.raise_for_status()
    scan_id = resp.json()["id"]
    for _ in range(240):
        scan = client.get(f"{base}/api/scans/{scan_id}").json()
        if scan["status"] in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.5)
    if scan["status"] != "COMPLETED":
        sys.exit(f"Scan of {target_id} did not complete: {scan.get('summary')}")
    return scan, client.get(f"{base}/api/scans/{scan_id}/findings").json()


def score(findings: list[dict], positives: set[tuple[str, str]]) -> list[dict]:
    """Collapse findings to unique (check, endpoint) pairs and label each one."""
    verdicts: dict[tuple[str, str], set[str]] = defaultdict(set)
    for f in findings:
        if f["status"] in ("SKIPPED", "ERROR") or f["endpoint"] == "N/A":
            continue
        verdicts[(f["test_id"], f["endpoint"])].add(f["status"])

    rows = []
    for pair, statuses in sorted(verdicts.items()):
        flagged = bool(statuses & FLAGGED)
        truth = pair in positives
        outcome = {(True, True): "TP", (True, False): "FP", (False, False): "TN", (False, True): "FN"}[(flagged, truth)]
        rows.append({"check": pair[0], "endpoint": pair[1], "flagged": flagged, "vulnerable": truth, "outcome": outcome})
    # Labelled positives the scanner never evaluated are misses too.
    for pair in sorted(positives - set(verdicts)):
        rows.append({"check": pair[0], "endpoint": pair[1], "flagged": False, "vulnerable": True, "outcome": "FN",
                     "note": "not evaluated"})
    return rows


def metrics(rows: list[dict]) -> dict:
    c = {k: sum(1 for r in rows if r["outcome"] == k) for k in ("TP", "FP", "TN", "FN")}
    tp, fp, tn, fn = c["TP"], c["FP"], c["TN"], c["FN"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    total = tp + fp + tn + fn
    return {**c, "total": total, "precision": precision, "recall": recall, "f1": f1,
            "accuracy": (tp + tn) / total if total else None,
            "fp_rate": fp / (fp + tn) if fp + tn else None}


def pct(x) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def table(title_col: str, groups: dict[str, dict]) -> str:
    out = [f"| {title_col} | Pairs | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |",
           "| :--- | --: | --: | --: | --: | --: | --: | --: | --: | --: |"]
    for name, m in groups.items():
        out.append(f"| {name} | {m['total']} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
                   f"{pct(m['precision'])} | {pct(m['recall'])} | {pct(m['f1'])} | {pct(m['accuracy'])} |")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="APIGuard detection accuracy evaluation")
    parser.add_argument("--backend", default="http://127.0.0.1:8000")
    parser.add_argument("--strict", action="store_true",
                        help="exit with status 1 if any pair is misclassified (used in CI)")
    args = parser.parse_args()

    truth = yaml.safe_load((HERE / "ground_truth.yaml").read_text(encoding="utf-8"))
    client = httpx.Client(timeout=60)

    try:
        health = client.get(f"{args.backend}/api/health").json()
    except httpx.HTTPError:
        sys.exit("APIGuard backend is not reachable on port 8000. Start it with scripts/run_all first.")
    offline = [k for k, v in health.get("demo_apis", {}).items() if v.get("status") != "online"]
    if offline:
        sys.exit(f"These targets are offline: {offline}. Start them with scripts/run_all first.")

    all_rows, per_target, scans = [], {}, {}
    for target_id, label, origin in TARGETS:
        print(f"Scanning {label} ...", flush=True)
        scan, findings = run_scan(client, args.backend, target_id)
        positives = {(p["check"], p["endpoint"]) for p in truth["targets"][target_id]["positives"]}
        rows = score(findings, positives)
        for r in rows:
            r.update(target=label, origin=origin, category=CATEGORY_OF[r["check"].split("-")[0]])
        all_rows.extend(rows)
        per_target[label] = metrics(rows)
        scans[label] = {k: scan.get(k) for k in ("id", "total_tests", "passed", "confirmed", "suspected", "errors", "duration_ms")}

    by_category = {c.replace("_", " ").title(): metrics([r for r in all_rows if r["category"] == c]) for c in CATEGORIES}
    by_origin = {
        "APIGuard demo API (own)": metrics([r for r in all_rows if r["origin"] == "own"]),
        "VAmPI (third-party)": metrics([r for r in all_rows if r["origin"] == "third-party"]),
        "**All targets**": metrics(all_rows),
    }
    vampi = truth["vampi_published_vulnerabilities"]
    vampi_found = []
    for v in vampi:
        hit = v["in_scope"] and v["checks"] and any(
            r["outcome"] == "TP" and r["check"] in v["checks"] and r["origin"] == "third-party" for r in all_rows)
        vampi_found.append({**v, "detected": bool(hit)})

    errors = [r for r in all_rows if r["outcome"] in ("FP", "FN")]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    in_scope = [v for v in vampi_found if v["in_scope"]]

    md = [
        "# APIGuard Detection Accuracy Evaluation", "",
        f"_Generated {now} by `evaluation/run_evaluation.py`._", "",
        "## Method",
        "Each target was scanned with all four check categories. Results were collapsed to unique "
        "(check, endpoint) pairs and compared with `evaluation/ground_truth.yaml`, whose labels were derived "
        "from the targets' source code rather than from scanner output. A pair counts as *flagged* when APIGuard "
        "reports it CONFIRMED or SUSPECTED; SKIPPED results are excluded.", "",
        "## Results by target", table("Target", per_target), "",
        "## Results by origin", table("Benchmark", by_origin), "",
        "## Results by category", table("Category", by_category), "",
        "## Scan statistics", "| Target | Checks run | PASS | CONFIRMED | SUSPECTED | Errors | Duration |",
        "| :--- | --: | --: | --: | --: | --: | --: |",
        *[f"| {t} | {s['total_tests']} | {s['passed']} | {s['confirmed']} | {s['suspected']} | {s['errors']} | {s['duration_ms']} ms |"
          for t, s in scans.items()], "",
        "## Coverage of VAmPI's published vulnerabilities",
        f"APIGuard detected **{sum(v['detected'] for v in in_scope)} of {len(in_scope)}** published VAmPI vulnerabilities "
        f"that fall inside its scope, and **{sum(v['detected'] for v in vampi_found)} of {len(vampi_found)}** overall.", "",
        "| VAmPI vulnerability | In APIGuard scope | Detected | Notes |", "| :--- | :-: | :-: | :--- |",
        *[f"| {v['name']} | {'yes' if v['in_scope'] else 'no'} | {'**yes**' if v['detected'] else 'no'} | "
          f"{', '.join(v.get('checks') or []) or v.get('reason', '')} |" for v in vampi_found], "",
        "## Misclassifications",
        *(["None: every evaluated (check, endpoint) pair matched the ground truth."] if not errors else
          [f"- **{r['outcome']}** {r['target']}: {r['check']} `{r['endpoint']}` {r.get('note', '')}" for r in errors]), "",
        "## Threats to validity",
        "- The demo API was written by the APIGuard authors; VAmPI is included as an independent benchmark.",
        "- Ground truth was labelled by the authors from source code; a reviewer can audit every label in `ground_truth.yaml`.",
        "- Small sample (4 targets); results show the checks behave as designed, not general real-world detection rates.",
        "- Detection depends on declared endpoint policies (`config/demo_targets.yaml`).",
    ]
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "evaluation_report.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (HERE / "results" / "evaluation_results.json").write_text(json.dumps({
        "generated": now, "per_target": per_target, "by_origin": by_origin, "by_category": by_category,
        "scans": scans, "vampi_coverage": vampi_found, "pairs": all_rows}, indent=2), encoding="utf-8")

    overall = by_origin["**All targets**"]
    print("\n" + table("Benchmark", by_origin))
    print(f"\nVAmPI published vulnerabilities detected: {sum(v['detected'] for v in in_scope)}/{len(in_scope)} in scope, "
          f"{sum(v['detected'] for v in vampi_found)}/{len(vampi_found)} overall")
    print(f"Overall: precision {pct(overall['precision'])}, recall {pct(overall['recall'])}, "
          f"FP rate {pct(overall['fp_rate'])}")
    print(f"\nReport written to {HERE / 'results' / 'evaluation_report.md'}")
    if args.strict and errors:
        sys.exit(f"{len(errors)} misclassified (check, endpoint) pairs - see the report.")


if __name__ == "__main__":
    main()
