# Processed RG outputs

'scrubd_cd_predictions.csv' and 'scrubd_cd_summary.json' retain the 469-contract RG run. 'scrubd_cd_function_ablation_run_matrix.csv' contains development variants; only Full and No Constraint Filtering map directly to the final paper as explained in the package README.

'db1_manifest.csv', 'db1_predictions.csv', and 'db1_summary.json' retain the local DB1 run. This manifest has 877 file rows and 195 unique hashes, whereas the paper?s Table 2 is defined over 895 labeled audit records. The DB1 Table 5 runtime is reconstructed from successful predictions after keeping one row per 'content_hash'.

Paths in these files document the original experiment workspace and may use Windows separators.
