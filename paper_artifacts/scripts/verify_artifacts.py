#!/usr/bin/env python3
"""Verify the paper artifact package."""

from __future__ import annotations

import csv
import hashlib
import math
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rows(relative_path: str) -> list[dict[str, str]]:
    with (ROOT / relative_path).open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def percentile_higher(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[math.ceil((len(ordered) - 1) * quantile)]


def verify_confusion_tables() -> None:
    files = (
        "source_data/table_1_contract_level_comparison.csv",
        "source_data/figure_5_ror_benchmark.csv",
        "source_data/table_2_dapp_audit_comparison.csv",
        "source_data/table_3_scrubd_cd_ablation.csv",
        "source_data/table_4_ror_ablation.csv",
    )
    for relative_path in files:
        for row in rows(relative_path):
            tp, fp, tn, fn = (int(row[key]) for key in ("tp", "fp", "tn", "fn"))
            assert tp + fp + tn + fn == int(row["n"]), (relative_path, row)
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            for key, value in (("precision", precision), ("recall", recall), ("f1", f1)):
                assert abs(float(row[key]) - value) <= 0.0001, (relative_path, key, row, value)


def verify_ror_dataset() -> None:
    manifest = rows("data/ror/manifest.csv")
    assert len(manifest) == 136
    labels = {0: 0, 1: 0}
    groups: dict[str, int] = {}
    for row in manifest:
        labels[int(row["y_true"])] += 1
        groups[row["source_group"]] = groups.get(row["source_group"], 0) + 1
    assert labels == {0: 58, 1: 78}, labels
    assert groups == {"smartreco_solidity_sources": 20, "ror_dataset_flat": 116}, groups
    assert len(list((ROOT / "data/ror/curated_cases").glob("*.sol"))) == 116


def verify_runtime() -> None:
    expected = {row["dataset"]: row for row in rows("source_data/table_5_runtime.csv")}
    scrubd = [
        float(row["runtime_seconds"])
        for row in rows("data/processed/scrubd_cd_predictions.csv")
        if row["status"] == "ok"
    ]
    db1_by_hash: dict[str, float] = {}
    for row in rows("data/processed/db1_predictions.csv"):
        if row["status"] == "ok" and row["content_hash"] not in db1_by_hash:
            db1_by_hash[row["content_hash"]] = float(row["runtime_seconds"])
    inputs = {"SCRUBD-CD": scrubd, "Real DApp audit": list(db1_by_hash.values())}
    for name, values in inputs.items():
        calculated = (
            statistics.median(values),
            statistics.mean(values),
            percentile_higher(values, 0.95),
        )
        paper = tuple(
            float(expected[name][key])
            for key in ("median_seconds", "mean_seconds", "p95_seconds")
        )
        assert all(round(value, 3) == target for value, target in zip(calculated, paper)), (
            name,
            calculated,
            paper,
        )


def verify_hashes() -> None:
    for row in rows("FILES_SHA256.csv"):
        path = ROOT / row["path"]
        canonical = path.read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(canonical).hexdigest() == row["sha256"], path
        assert len(canonical) == int(row["bytes"]), path


def main() -> None:
    verify_confusion_tables()
    verify_ror_dataset()
    verify_runtime()
    verify_hashes()
    print("All paper artifact checks passed.")


if __name__ == "__main__":
    main()
