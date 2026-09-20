#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from run_smartbugs_negative_evaluation import (
    compute_summary,
    write_latex_table,
    write_paper_text,
    write_predictions_csv,
    write_summary_markdown,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_DIR = ROOT / "results" / "smartbugs_negative_eval"
DEFAULT_FALLBACK_DIR = ROOT / "results" / "smartbugs_negative_five_coverage"
DEFAULT_OUTPUT_DIR = ROOT / "results" / "smartbugs_negative_hybrid_coverage"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Merge exact SmartBugs negative results with bounded fallback records for "
            "previously non-analyzed cases."
        )
    )
    parser.add_argument("--base-dir", default=str(DEFAULT_BASE_DIR), help="Directory containing exact baseline results.")
    parser.add_argument(
        "--fallback-dir",
        default=str(DEFAULT_FALLBACK_DIR),
        help="Directory containing bounded fallback records.",
    )
    parser.add_argument("-o", "--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Merged output directory.")
    parser.add_argument(
        "--replace-all-fallback",
        action="store_true",
        help="Replace base records for every fallback case instead of only non-ok base records.",
    )
    return parser.parse_args()


def load_records(result_dir: Path) -> list[dict[str, Any]]:
    summary_path = result_dir / "summary.json"
    if not summary_path.exists():
        raise SystemExit(f"Missing summary.json: {summary_path}")
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    return list(data.get("records") or [])


def copy_fallback_reports(fallback_dir: Path, output_dir: Path, records: list[dict[str, Any]]) -> None:
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        report_dir = Path(record.get("report_dir") or "")
        if not report_dir.is_absolute():
            report_dir = ROOT / report_dir
        if not report_dir.exists():
            continue
        target = reports_dir / record["case_id"]
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(report_dir, target)
        record["report_dir"] = str(target.resolve().relative_to(ROOT.resolve()))
        raw_log = target / "raw.log"
        if raw_log.exists():
            record["raw_log"] = str(raw_log.resolve().relative_to(ROOT.resolve()))


def main() -> int:
    args = parse_args()
    base_dir = Path(args.base_dir)
    fallback_dir = Path(args.fallback_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    base_records = load_records(base_dir)
    fallback_records = load_records(fallback_dir)
    fallback_by_case = {record["case_id"]: dict(record) for record in fallback_records}

    merged_records: list[dict[str, Any]] = []
    used_fallback: list[dict[str, Any]] = []
    for base_record in base_records:
        case_id = base_record["case_id"]
        fallback = fallback_by_case.get(case_id)
        should_replace = bool(
            fallback
            and fallback.get("status") == "ok"
            and (args.replace_all_fallback or base_record.get("status") != "ok")
        )
        if should_replace:
            merged = dict(fallback)
            merged["fallback_replaced_base_status"] = base_record.get("status")
            used_fallback.append(merged)
        else:
            merged = dict(base_record)
            merged.setdefault("bounded_ccr", 0)
            merged.setdefault("bounded_ccr_truncated", 0)
            merged["fallback_replaced_base_status"] = ""
        merged_records.append(merged)

    missing = sorted(set(fallback_by_case) - {record["case_id"] for record in base_records})
    if missing:
        raise SystemExit(f"Fallback records not present in base results: {', '.join(missing)}")

    copy_fallback_reports(fallback_dir, output_dir, used_fallback)

    merged_records.sort(key=lambda record: (record["category"], record["case_id"]))
    summary = compute_summary(merged_records)
    summary["fallback_cases"] = len(used_fallback)
    summary["fallback_case_ids"] = [record["case_id"] for record in used_fallback]
    full_summary = {"summary": summary, "records": merged_records}

    (output_dir / "summary.json").write_text(json.dumps(full_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_predictions_csv(output_dir / "smartbugs_negative_predictions.csv", merged_records)
    write_summary_markdown(output_dir / "paper_results.md", summary, merged_records)
    write_latex_table(output_dir / "paper_table.tex", summary)
    write_paper_text(output_dir / "paper_paragraph.md", summary)

    print(f"Merged {len(merged_records)} records with {len(used_fallback)} bounded fallback replacements.")
    print(f"- Summary JSON: {output_dir / 'summary.json'}")
    print(f"- Predictions CSV: {output_dir / 'smartbugs_negative_predictions.csv'}")
    print(f"- Paper results MD: {output_dir / 'paper_results.md'}")
    print(f"- LaTeX table: {output_dir / 'paper_table.tex'}")
    print(f"- Paper paragraph: {output_dir / 'paper_paragraph.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
