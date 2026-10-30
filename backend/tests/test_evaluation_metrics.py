"""The accuracy-evaluation scoring logic itself is tested, so reported metrics can be trusted."""
import yaml
from pathlib import Path

from evaluation.run_evaluation import metrics, score

ROOT = Path(__file__).resolve().parents[2]


def test_score_collapses_probes_and_labels_outcomes():
    findings = [
        {"test_id": "AUTHZ-001", "endpoint": "/a", "status": "CONFIRMED"},
        {"test_id": "INPUT-001", "endpoint": "/b", "status": "PASS"},
        {"test_id": "INPUT-001", "endpoint": "/b", "status": "CONFIRMED"},   # same pair, any flag counts
        {"test_id": "DATA-001", "endpoint": "/c", "status": "SUSPECTED"},     # flagged but not vulnerable
        {"test_id": "AUTH-001", "endpoint": "/d", "status": "PASS"},
        {"test_id": "AUTHZ-002", "endpoint": "N/A", "status": "SKIPPED"},     # ignored
    ]
    positives = {("AUTHZ-001", "/a"), ("INPUT-001", "/b"), ("AUTH-002", "/never-probed")}
    rows = {(r["check"], r["endpoint"]): r["outcome"] for r in score(findings, positives)}
    assert rows == {("AUTHZ-001", "/a"): "TP", ("INPUT-001", "/b"): "TP", ("DATA-001", "/c"): "FP",
                    ("AUTH-001", "/d"): "TN", ("AUTH-002", "/never-probed"): "FN"}


def test_metrics_formulae():
    rows = [{"outcome": o} for o in ["TP"] * 8 + ["FP"] * 2 + ["TN"] * 9 + ["FN"] * 1]
    m = metrics(rows)
    assert (m["precision"], m["recall"], m["accuracy"]) == (0.8, 8 / 9, 17 / 20)
    assert round(m["f1"], 4) == round(2 * 0.8 * (8 / 9) / (0.8 + 8 / 9), 4)
    assert metrics([{"outcome": "TN"}])["precision"] is None


def test_ground_truth_file_is_well_formed():
    data = yaml.safe_load((ROOT / "evaluation" / "ground_truth.yaml").read_text(encoding="utf-8"))
    assert set(data["targets"]) == {"target-vulnerable-demo", "target-secure-demo",
                                    "target-vampi-vulnerable", "target-vampi-secure"}
    for target in data["targets"].values():
        for p in target["positives"]:
            assert p["check"] and p["endpoint"] and p["why"]
    assert len(data["vampi_published_vulnerabilities"]) == 9
