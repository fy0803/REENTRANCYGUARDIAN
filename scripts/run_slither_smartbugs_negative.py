#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_slither_smartbugs_positive import (
    DEFAULT_VERSIONS_CSV,
    SLITHER_DETECTORS,
    PositiveCase,
    display_path,
    evaluate_case,
    load_versions,
)


DEFAULT_DATASET_DIR = ROOT / "datasets" / "smartbugs-curated" / "dataset"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "slither_smartbugs_negative"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Slither's reentrancy detectors on SmartBugs Curated non-reentrancy categories."
    )
    parser.add_argument("--dataset-dir", default=str(DEFAULT_DATASET_DIR), help="Path to smartbugs-curated/dataset.")
    parser.add_argument("--versions-csv", default=str(DEFAULT_VERSIONS_CSV), help="Path to SmartBugs versions.csv.")
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory.")
    parser.add_argument(
        "--exclude-category",
        action="append",
        default=["reentrancy"],
        help="Dataset category to exclude. Defaults to reentrancy.",
    )
    parser.add_argument("--category", action="append", help="Run only this category. Can be supplied multiple times.")
    parser.add_argument("--case", action="append", dest="selected_cases", help="Run only this generated case id.")
    parser.add_argument("--limit", type=int, help="Maximum number of samples to evaluate.")
    parser.add_argument("--process-timeout", type=int, default=300, help="Hard timeout per Slither run.")
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(2, os.cpu_count() or 1)),
        help="Number of parallel Slither processes.",
    )
    parser.add_argument("--force", action="store_true", help="Re-run cases even if cached records exist.")
    return parser.parse_args()


def collect_cases(
    dataset_dir: Path,
    excluded_categories: set[str],
    selected_categories: Optional[set[str]],
    selected_case_ids: Optional[set[str]],
    limit: Optional[int],
) -> list[PositiveCase]:
    cases: list[PositiveCase] = []
    for category_dir in sorted(dataset_dir.iterdir(), key=lambda path: path.name.lower()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        if category in excluded_categories:
            continue
        if selected_categories and category not in selected_categories:
            continue

        for contract_path in sorted(category_dir.rglob("*.sol"), key=lambda path: str(path).lower()):
            case_id = f"{category}__{contract_path.stem}"
            if selected_case_ids and case_id not in selected_case_ids:
                continue
            dataset_path = contract_path.relative_to(dataset_dir.parent).as_posix()
            cases.append(PositiveCase(case_id=case_id, contract_path=contract_path, dataset_path=dataset_path))

    missing = sorted((selected_case_ids or set()) - {case.case_id for case in cases})
    if missing:
        raise SystemExit(f"Unknown negative case ids: {', '.join(missing)}")

    if limit is not None:
        cases = cases[:limit]
    return cases


def write_predictions_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fieldnames = [
        "case_id",
        "category",
        "input_path",
        "status",
        "false_positive",
        "finding_count",
        "detectors",
        "solc_version",
        "solc_source",
        "runtime_seconds",
        "report_dir",
        "raw_log",
        "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow({field: record.get(field) for field in fieldnames})


def compute_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    total_cases = len(records)
    ok_cases = sum(1 for record in records if record["status"] == "ok")
    fp_cases = sum(int(record["false_positive"]) for record in records)
    tn_cases = sum(1 for record in records if record["status"] == "ok" and not int(record["false_positive"]))
    failed_cases = sum(1 for record in records if record["status"] == "analysis_failed")
    timeout_cases = sum(1 for record in records if record["status"] == "timeout")
    avg_runtime = (
        sum(float(record["runtime_seconds"]) for record in records if record["status"] == "ok") / ok_cases
        if ok_cases
        else None
    )

    by_category: dict[str, dict[str, Any]] = {}
    for category in sorted({record["category"] for record in records}):
        category_records = [record for record in records if record["category"] == category]
        category_ok = sum(1 for record in category_records if record["status"] == "ok")
        category_fp = sum(int(record["false_positive"]) for record in category_records)
        by_category[category] = {
            "cases": len(category_records),
            "analyzed": category_ok,
            "true_negatives": sum(
                1 for record in category_records if record["status"] == "ok" and not int(record["false_positive"])
            ),
            "false_positives": category_fp,
            "failed": sum(1 for record in category_records if record["status"] == "analysis_failed"),
            "timeout": sum(1 for record in category_records if record["status"] == "timeout"),
            "fpr_analyzed": category_fp / category_ok if category_ok else None,
        }

    return {
        "tool": "Slither",
        "detectors": SLITHER_DETECTORS,
        "total_cases": total_cases,
        "ok_cases": ok_cases,
        "true_negative_cases": tn_cases,
        "false_positive_cases": fp_cases,
        "analysis_failed_cases": failed_cases,
        "timeout_cases": timeout_cases,
        "total_findings": sum(int(record["finding_count"]) for record in records),
        "fpr_analyzed": fp_cases / ok_cases if ok_cases else None,
        "fpr_all": fp_cases / total_cases if total_cases else None,
        "avg_runtime_seconds": avg_runtime,
        "status_summary": {
            status: sum(1 for record in records if record["status"] == status)
            for status in sorted({str(record["status"]) for record in records})
        },
        "by_category": by_category,
    }


def format_rate(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.4f}"


def write_summary_markdown(path: Path, summary: dict[str, Any], records: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    lines.append("# Slither SmartBugs Negative Evaluation")
    lines.append("")
    lines.append("- Dataset: `datasets/smartbugs-curated/dataset`")
    lines.append("- Negative-sample definition: all categories except `reentrancy`.")
    lines.append(f"- Detectors: `{summary['detectors']}`")
    lines.append("- Metric note: this subset is used to measure false positives for reentrancy detection.")
    lines.append("")
    lines.append("## Main Table")
    lines.append("")
    lines.append("| Tool | Cases | Analyzed | TN | FP | Failed | Timeout | FPR (Analyzed) | FPR (All) | Avg Runtime (s) | Findings |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(
        "| `{tool}` | {total_cases} | {ok_cases} | {true_negative_cases} | {false_positive_cases} | "
        "{analysis_failed_cases} | {timeout_cases} | {fpr_analyzed} | {fpr_all} | {avg_runtime_seconds} | "
        "{total_findings} |".format(
            **{
                **summary,
                "fpr_analyzed": format_rate(summary["fpr_analyzed"]),
                "fpr_all": format_rate(summary["fpr_all"]),
                "avg_runtime_seconds": format_rate(summary["avg_runtime_seconds"]),
            }
        )
    )
    lines.append("")
    lines.append("## Category Breakdown")
    lines.append("")
    lines.append("| Category | Cases | Analyzed | TN | FP | Failed | Timeout | FPR (Analyzed) |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for category, values in summary["by_category"].items():
        lines.append(
            f"| `{category}` | {values['cases']} | {values['analyzed']} | {values['true_negatives']} | "
            f"{values['false_positives']} | {values['failed']} | {values['timeout']} | "
            f"{format_rate(values['fpr_analyzed'])} |"
        )

    lines.append("")
    lines.append("## False Positive Cases")
    lines.append("")
    fp_records = [record for record in records if int(record["false_positive"])]
    if not fp_records:
        lines.append("No false positives were reported.")
    else:
        lines.append("| Case | Category | Findings | Detectors | Runtime (s) |")
        lines.append("| --- | --- | ---: | --- | ---: |")
        for record in fp_records:
            lines.append(
                f"| `{record['case_id']}` | `{record['category']}` | {record['finding_count']} | "
                f"{record['detectors'] or 'None'} | {float(record['runtime_seconds']):.3f} |"
            )

    non_ok = [record for record in records if record["status"] != "ok"]
    if non_ok:
        lines.append("")
        lines.append("## Non-Analyzed Cases")
        lines.append("")
        lines.append("| Case | Category | Status | Error |")
        lines.append("| --- | --- | --- | --- |")
        for record in non_ok:
            error = (record.get("error") or "").replace("\n", " ").replace("|", "\\|")
            lines.append(f"| `{record['case_id']}` | `{record['category']}` | `{record['status']}` | {error} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_latex_table(path: Path, summary: dict[str, Any]) -> None:
    table = rf"""\begin{{table}}[t]
\centering
\caption{{Slither false-positive results on the non-reentrancy categories of SmartBugs Curated.}}
\label{{tab:slither-smartbugs-negative}}
\begin{{tabular}}{{lrrrrrrrr}}
\toprule
Tool & Cases & Analyzed & TN & FP & Failed & Timeout & FPR$_{{analyzed}}$ & FPR$_{{all}}$ \\
\midrule
Slither & {summary['total_cases']} & {summary['ok_cases']} & {summary['true_negative_cases']} & {summary['false_positive_cases']} & {summary['analysis_failed_cases']} & {summary['timeout_cases']} & {format_rate(summary['fpr_analyzed'])} & {format_rate(summary['fpr_all'])} \\
\bottomrule
\end{{tabular}}
\end{{table}}
"""
    path.write_text(table, encoding="utf-8")


def write_paper_text(path: Path, summary: dict[str, Any]) -> None:
    text = (
        "For the negative-sample experiment, we ran Slither's built-in reentrancy detectors on all "
        "non-reentrancy categories in SmartBugs Curated. "
        f"Slither successfully analyzed {summary['ok_cases']} out of {summary['total_cases']} contracts. "
        f"Among the analyzed contracts, {summary['true_negative_cases']} were left unreported and "
        f"{summary['false_positive_cases']} produced at least one reentrancy warning, giving an analyzed-case "
        f"false-positive rate of {format_rate(summary['fpr_analyzed'])}. Counting non-analyzed contracts in the "
        f"denominator, the end-to-end false-positive rate is {format_rate(summary['fpr_all'])}.\n"
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    args = parse_args()
    dataset_dir = Path(args.dataset_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cases = collect_cases(
        dataset_dir=dataset_dir,
        excluded_categories=set(args.exclude_category or []),
        selected_categories=set(args.category) if args.category else None,
        selected_case_ids=set(args.selected_cases) if args.selected_cases else None,
        limit=args.limit,
    )
    if not cases:
        raise SystemExit(f"No negative Solidity files found under {dataset_dir}")

    versions = load_versions(Path(args.versions_csv))
    categories = {case.case_id: case.dataset_path.split("/")[1] for case in cases}

    print(f"Selected {len(cases)} SmartBugs negative cases.")
    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(evaluate_case, case, args, output_dir, versions): case for case in cases}
        for index, future in enumerate(as_completed(futures), start=1):
            case = futures[future]
            try:
                record = future.result()
            except Exception as exc:
                record = {
                    "case_id": case.case_id,
                    "input_path": display_path(case.contract_path),
                    "status": "script_failed",
                    "detected": 0,
                    "finding_count": 0,
                    "detectors": "",
                    "solc_version": None,
                    "solc_source": None,
                    "runtime_seconds": 0.0,
                    "report_dir": "",
                    "raw_log": "",
                    "error": str(exc),
                }
            record["category"] = categories.get(case.case_id, "unknown")
            record["false_positive"] = int(record.get("status") == "ok" and int(record.get("finding_count") or 0) > 0)
            records.append(record)
            print(
                f"[{index}/{len(cases)}] {case.case_id} -> status={record['status']}, "
                f"fp={record['false_positive']}, findings={record['finding_count']}, solc={record.get('solc_version')}"
            )

    records.sort(key=lambda record: (record["category"], record["case_id"]))
    summary = compute_summary(records)
    (output_dir / "summary.json").write_text(
        json.dumps({"summary": summary, "records": records}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_predictions_csv(output_dir / "slither_negative_predictions.csv", records)
    write_summary_markdown(output_dir / "paper_results.md", summary, records)
    write_latex_table(output_dir / "paper_table.tex", summary)
    write_paper_text(output_dir / "paper_paragraph.md", summary)

    print("\nArtifacts written:")
    print(f"- Summary JSON: {output_dir / 'summary.json'}")
    print(f"- Predictions CSV: {output_dir / 'slither_negative_predictions.csv'}")
    print(f"- Paper results MD: {output_dir / 'paper_results.md'}")
    print(f"- LaTeX table: {output_dir / 'paper_table.tex'}")
    print(f"- Paper paragraph: {output_dir / 'paper_paragraph.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
