# Paper-to-Pattern Abstraction Notes

This document records how we separate cache side-channel literature into two layers:

1. **Attack observation method**: how the attacker observes cache state. In this prototype, this is fixed as a Prime+Probe-style observation model.
2. **Victim leakage pattern**: what kind of victim memory-access/control-flow behavior creates a secret-dependent cache footprint. These vulnerable victim patterns are encoded in `scenarios/llm_extracted_patterns.json` and validated in the simulator.

The project does **not** claim to reproduce the full real-world attacks from these papers. Instead, it abstracts representative victim-side leakage patterns into simplified test scenarios.

## Attack / Leakage Pattern Scenarios

`scenarios/llm_extracted_patterns.json` is intentionally kept to **vulnerable victim leakage patterns only**. Program-level mitigations such as constant-time scan or random padding are moved to `scenarios/defense_scenarios.json`, where they are compared against corresponding no-defense cases.

| Source concept / representative literature | Layer extracted | Simplified vulnerable victim program pattern | Scenario name | Expected leakage | Why it fits our simulator |
|---|---|---|---|---|---|
| AES cache attacks and countermeasures; table-driven AES timing/collision attacks | Victim data-memory access | `access(table_base + secret * line_size)` | `secret_dependent_table_lookup` | High | Prime+Probe can observe which cache set was disturbed by the secret-indexed lookup. |
| AES-style table-driven implementations with multiple lookup operations | Victim data-memory footprint | `for t in tables: access(table_base[t] + f(secret,t) * line_size)` | `multi_table_lookup_footprint` | High | A secret can create a wider cache footprint over several sets, not just one. |
| Cache attacks on secret-dependent control flow / code footprints | Victim control-flow/code footprint | `if secret_bit: access(region_true) else: access(region_false)` | `secret_dependent_branch_footprint` | Medium | This leaks one secret bit / branch direction, so it is partial leakage for a larger secret space. |
| Secret-dependent variable work / variable memory footprint | Victim control-flow + memory footprint | `for i in range(secret+1): access(base + i*line_size)` | `secret_dependent_loop_count` | High | The number of disturbed sets changes with the secret. |
| Prime+Probe observes cache-set activity rather than exact addresses | Observation granularity limit applied to victim lookup | `access(table_base + secret*stride)` with multiple secrets aliasing to the same set | `set_aliasing_table_lookup` | Medium | The trace reveals the set group, but not the exact secret among values sharing a set. |

## Current implementation boundary

- Fixed attacker observation model: **Prime+Probe-style**.
- Main variable under test in pattern comparison: **vulnerable victim memory-access/control-flow patterns**.
- Simulator output: cache probe timing vectors.
- Leakage metric: nearest-mean secret prediction accuracy compared with random baseline.

## Defense / Mitigation Mapping

The defense comparison is stored separately in `scenarios/defense_scenarios.json`. It does **not** claim to defend every possible cache attack method. The attacker observation method is still fixed as Prime+Probe-style monitoring. The defense experiment asks a narrower question:

> Given a representative victim leakage pattern, does a simplified program-level or system-level mitigation reduce the evaluator's ability to infer the secret?

| Base leakage pattern | No-defense scenario | Defense / mitigation scenario | Defense idea | Expected result |
|---|---|---|---|---|
| Single table lookup | `table_lookup_no_defense` | `table_lookup_constant_time_scan` | Touch all candidate table entries regardless of the secret | Low leakage |
| Single table lookup | `table_lookup_no_defense` | `table_lookup_random_padding` | Add random extra accesses while keeping original secret-dependent access | Medium leakage |
| Single table lookup | `table_lookup_no_defense` | `table_lookup_partitioned_cache` | Map victim secret-dependent accesses outside attacker-monitored sets | Low leakage |
| Multi-table lookup footprint | `multi_table_no_defense` | `multi_table_constant_time_footprint` | Touch every candidate multi-table footprint in fixed order | Low leakage |
| Secret-dependent branch footprint | `branch_no_defense` | `branch_balanced_footprint` | Touch both branch footprints regardless of branch direction | Low leakage |
| Secret-dependent loop count | `loop_count_no_defense` | `loop_count_fixed_count_padding` | Always execute/touch a fixed number of iterations/locations | Low leakage |

This separation keeps the project story consistent:

1. Extract representative **vulnerable victim leakage patterns** from public cache side-channel concepts.
2. Encode those attack/leakage patterns in `llm_extracted_patterns.json`.
3. Encode corresponding no-defense/mitigation comparisons in `defense_scenarios.json`.
4. Validate both under the same Prime+Probe-style observation model.
5. Use prediction accuracy over random baseline as the leakage score.

## Important limitations

- The simulator uses normalized timing units, not hardware-calibrated cycle counts.
- It models cache sets, ways, tags, LRU, hit/miss, and additive timing noise, but not real CPU effects such as prefetching, out-of-order execution, interrupts, TLBs, or OS scheduling.
- The patterns are simplified test scenarios inspired by public concepts; they are not full reproductions of the original attacks.
