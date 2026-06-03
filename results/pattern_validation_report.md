# Pattern Validation Report

This report is generated from the reviewed scenario JSON files and simulator results. It links the LLM-assisted candidate/review workflow to the executable Prime+Probe-style validation backend.

## Scope

- The simulator fixes the attacker observation model as **Prime+Probe-style**.
- The executable attack-side scenarios are **victim program leakage patterns**, not full real-hardware attacks.
- LLM-style raw candidates are **not executed directly**; only reviewed and simulator-compatible scenarios under `scenarios/` are executed.
- Timing uses normalized simulator units rather than hardware-calibrated cycle counts.

## Vulnerable Pattern Validation

| Scenario | Raw candidate | Pattern type | Expected | Accuracy | Baseline | Leakage label | Notes |
|---|---|---|---|---:|---:|---|---|
| `secret_dependent_table_lookup` | `raw_table_lookup_001` | `table_lookup` | high | 1.0000 | 0.2500 | high leakage | Table-driven cryptographic implementations such as AES T-tables use secret-dependent values to index memory tables; c... |
| `multi_table_lookup_footprint` | `raw_multi_table_002` | `multi_table_lookup` | high | 1.0000 | 0.2500 | high leakage | AES-style table-driven code often performs multiple table-like memory accesses during one sensitive operation, creati... |
| `secret_dependent_branch_footprint` | `raw_branch_003` | `secret_dependent_branch` | medium | 0.4833 | 0.2500 | partial / medium leakage | Constant-time guidance and cache-side-channel analysis identify secret-dependent branches/control flow as a leakage s... |
| `secret_dependent_loop_count` | `raw_loop_count_004` | `loop_count` | high | 1.0000 | 0.2500 | high leakage | Variable-time secret-dependent control flow can change how many memory locations are touched; the cache footprint siz... |
| `set_aliasing_table_lookup` | `raw_set_aliasing_005` | `set_aliasing_lookup` | medium | 0.5233 | 0.1250 | partial / medium leakage | Prime+Probe observes cache-set disturbance rather than exact addresses. Different logical table entries can alias to ... |

## Defense / Mitigation Validation

| Defense group | Scenario | Case type | Pattern type | Accuracy | Baseline | Interpretation |
|---|---|---|---|---:|---:|---|
| table_lookup | `table_lookup_no_defense` | no_defense | `table_lookup` | 1.0000 | 0.2500 | control baseline |
| table_lookup | `table_lookup_constant_time_scan` | program_level_defense | `constant_time_scan` | 0.2767 | 0.2500 | effective in this simplified model |
| table_lookup | `table_lookup_random_padding` | program_level_mitigation | `random_padding` | 0.5933 | 0.2500 | reduces but does not eliminate leakage |
| table_lookup | `table_lookup_partitioned_cache` | system_level_mitigation | `partitioned_cache` | 0.2867 | 0.2500 | effective in this simplified model |
| multi_table_lookup | `multi_table_no_defense` | no_defense | `multi_table_lookup` | 1.0000 | 0.2500 | control baseline |
| multi_table_lookup | `multi_table_constant_time_footprint` | program_level_defense | `multi_table_constant_time` | 0.2800 | 0.2500 | effective in this simplified model |
| branch_footprint | `branch_no_defense` | no_defense | `secret_dependent_branch` | 0.4833 | 0.2500 | control baseline |
| branch_footprint | `branch_balanced_footprint` | program_level_defense | `balanced_branch` | 0.2300 | 0.2500 | effective in this simplified model |
| loop_count | `loop_count_no_defense` | no_defense | `loop_count` | 1.0000 | 0.2500 | control baseline |
| loop_count | `loop_count_fixed_count_padding` | program_level_defense | `fixed_loop_count` | 0.2767 | 0.2500 | effective in this simplified model |

## Partial Leakage Analysis

Accuracy alone can hide partial leakage. The following patterns leak a coarser secret group even when exact-secret recovery is limited.

| Pattern | Exact accuracy | Exact baseline | Group rule | Group accuracy | Group baseline | Confusion matrix |
|---|---:|---:|---|---:|---:|---|
| `set_aliasing_table_lookup` | 0.5233 | 0.1250 | cache_set_group = secret mod 4 | 1.0000 | 0.2500 | `results/confusion_matrix_set_aliasing_table_lookup.csv` |
| `secret_dependent_branch_footprint` | 0.4833 | 0.2500 | branch_group = secret mod 2 | 1.0000 | 0.5000 | `results/confusion_matrix_secret_dependent_branch_footprint.csv` |

## Takeaways

1. Strong secret-dependent memory footprints, such as single-table and multi-table lookup, are easy to classify in the simplified Prime+Probe-style model.
2. Branch and set-aliasing cases show **partial leakage**: the evaluator may not always recover the exact secret, but it can recover a secret-dependent group such as branch direction or cache-set group.
3. Program-level constant-footprint defenses and partitioning-style isolation reduce accuracy close to the random baseline in this model.
4. Random padding reduces leakage but does not remove the underlying secret-dependent signal.

## Limitations

- This is not a real hardware Prime+Probe implementation.
- The cache model is simplified: fixed sets/ways, LRU replacement, normalized hit/miss latency, and additive Gaussian noise.
- The system does not automatically read PDFs or directly execute raw LLM outputs.
- Results indicate leakage potential in a controlled model, not real-world exploit success.
