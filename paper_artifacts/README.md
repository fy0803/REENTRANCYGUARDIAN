# REENTRANCY GUARDIAN paper artifacts

This is the compact research-data and reproducibility package for:

> Fuyang Wang, Ning Duan, Junyu Dou, and Gang Du, ?Semantics-Enhanced Static Analysis for Detecting Cross-Contract and Read-Only Reentrancy in Smart Contracts.?

Version 1.0.0, prepared 2026-09-20.

## Included data

| Evaluation set | Paper scale | Included here |
|---|---:|---|
| SCRUBD-CD | 469 contracts; 746 function samples | Final table data, RG predictions/summary, and a retained ablation run matrix |
| ROR benchmark | 136 samples: 78 positive, 58 safe | Full manifest/labels, all 116 study-curated Solidity cases, RG evaluation, and Figure 5 source data |
| SliSE DB1 | 895 labeled audit records: 81 positive, 814 negative | Final table data plus the local RG manifest/predictions used to reconstruct runtime |

Bulky generated reports and third-party contract trees are excluded. The omitted SCRUBD tool-output tree alone is about 2.7 GB and is unnecessary for the paper?s aggregate tables.

## Paper-to-file map

| Paper item | Primary file | Supporting file |
|---|---|---|
| Table 1 | 'source_data/table_1_contract_level_comparison.csv' | 'data/processed/scrubd_cd_predictions.csv' |
| Figure 5 | 'source_data/figure_5_ror_benchmark.csv' | 'data/ror/evaluation_current.csv' |
| Table 2 | 'source_data/table_2_dapp_audit_comparison.csv' | Final-manuscript aggregate; see DB1 caveat |
| Table 3 | 'source_data/table_3_scrubd_cd_ablation.csv' | 'data/processed/scrubd_cd_function_ablation_run_matrix.csv' |
| Table 4 | 'source_data/table_4_ror_ablation.csv' | Final-manuscript aggregate |
| Table 5 | 'source_data/table_5_runtime.csv' | RG prediction files under 'data/processed/' |

Run 'python paper_artifacts/scripts/verify_artifacts.py' from the repository root to check confusion matrices, ROR counts, runtime reconstruction, and SHA-256 hashes.

## Provenance and redistribution

- SCRUBD-CD: https://github.com/InPlusLab/ReentrancyStudy-Data
- SmartReco: https://github.com/jwzhang-zzz/smartReco
- SliSE DB1: https://github.com/SliSE-SC/SliSE

The ROR set combines 20 public SmartReco-derived positive samples with 116 cases curated in this work. The 20 SmartReco source trees are not copied here; their metadata and annotations remain in 'data/ror/manifest.csv'. The 116 curated single-file cases are included under 'data/ror/curated_cases/'.

SCRUBD-CD and SliSE DB1 raw Solidity trees are not redistributed because no repository-level redistribution license was identified in the inspected local checkouts. Retrieve them from upstream and follow their terms. This package includes the authors? derived RG outputs and exact final-paper aggregates.

No blanket license is asserted over third-party material. Each bundled Solidity sample retains its SPDX identifier; see 'LICENSES/README.md'.

## DB1 caveat

The paper reports 895 labeled DB1 records for Table 2. The retained local execution manifest contains 877 Solidity files representing 195 unique source hashes. It reconstructs the Table 5 runtime row after successful-run and duplicate handling, but is not a row-for-row reconstruction of the 895-record Table 2 matrix. Table 2 is therefore marked as a final-manuscript aggregate.

## Source-data caveat

Table 3?s Full and No Constraint Filtering rows match the retained function-level run matrix using 'source_or_target_function_match'. Detailed final run matrices for Base ICFG and No State Access were not found in the workspace; the exact final-manuscript aggregates are preserved without claiming row-level reconstruction.

For journal archiving, create a tagged GitHub release, archive it in Zenodo or another trusted repository, and add the resulting DOI to 'CITATION.cff' and the manuscript Data Availability statement.
