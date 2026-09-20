# ROR benchmark

The final benchmark has 136 samples: 20 SmartReco-derived positives plus 116 study-curated files (58 positive and 58 safe).

- 'manifest.csv': full provenance and location annotations.
- 'labels.csv': compact labels and locations.
- 'run_targets.csv': historical targets in the full workspace.
- 'evaluation_current.csv': RG outcome for all samples.
- 'metrics_current.csv': RG aggregate metrics.
- 'curated_cases/': 116 study-curated Solidity files.

The 20 SmartReco source trees are not redistributed. Their chain, address, target, labels, and annotations remain in the manifest. Historical paths in the CSV files need not resolve in a fresh clone. For 'ror_dataset_flat' rows, map the target filename to 'curated_cases/'.

A positive RG result matches the annotated vulnerable entry function or corresponding state-inconsistency interval. Every bundled Solidity file preserves its SPDX header.
