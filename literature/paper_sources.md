# Paper Sources for Pattern Abstraction

This file documents the literature/source layer for the project. Its purpose is **not** to reproduce the full attacks in these papers. Instead, we use representative cache side-channel literature to separate two ideas:

1. **Attack observation method** — how the attacker observes cache state. In our current prototype this is fixed as **Prime+Probe-style observation**.
2. **Victim program leakage pattern** — what kind of victim memory-access/control-flow behavior creates a secret-dependent cache footprint. These are the patterns we encode as JSON scenarios and validate with the simulator.

The current simulator uses a trace-driven cache model with sets, ways, tags, LRU replacement, hit/miss timing, and additive timing noise. Therefore, we only select source concepts that can reasonably be reduced to address traces and cache-set timing observations.

---

## Source Selection Criteria

We selected sources using these criteria:

- The source is representative or commonly cited in cache side-channel literature.
- The source clearly motivates either Prime+Probe-style observation, secret-dependent memory/control-flow behavior, or constant-time/partitioning-style mitigation.
- The source concept can be mapped into our simplified trace-driven simulator without claiming full real-hardware reproduction.
- The source helps distinguish **attacker method** from **victim leakage pattern**.

---

## Selected Literature and How We Use It

| ID | Source | Why it is included | Layer used in our project | Pattern / experiment motivated |
|---|---|---|---|---|
| S1 | Daniel J. Bernstein, *Cache-timing attacks on AES* (2005) | Early influential AES cache timing work; motivates that table lookups are not constant-time on real machines. | Victim data-memory access | `secret_dependent_table_lookup` |
| S2 | Osvik, Shamir, and Tromer, *Cache Attacks and Countermeasures: the Case of AES* (2005/2006; later J. Cryptology version) | Explicitly describes cache-state leakage revealing memory access patterns and data-dependent table lookups. | Victim memory-access pattern + attack/countermeasure background | `secret_dependent_table_lookup`, `multi_table_lookup_footprint` |
| S3 | Bonneau and Mironov, *Cache-Collision Timing Attacks Against AES* (CHES 2006) | Focuses on table-driven AES and timing variation from cache collisions in lookup sequences. | Victim table-lookup footprint and cache-collision idea | `multi_table_lookup_footprint`, `set_aliasing_table_lookup` |
| S4 | Liu et al., *Last-Level Cache Side-Channel Attacks are Practical* (IEEE S&P 2015) | Representative practical LLC Prime+Probe paper; motivates fixing our attacker observation method as Prime+Probe-style. | Attack observation method | Prime+Probe-style simulator flow: prime → victim → probe |
| S5 | Zhao et al., *Last-Level Cache Side-Channel Attacks Are Feasible in the Modern Public Cloud* (ASPLOS 2024) | Shows modern cloud LLC Prime+Probe setting, target LLC sets, eviction sets, and noisy environment. | Attack observation method + noise motivation + set-level monitoring | Noise sweep; monitored-set abstraction; `set_aliasing_table_lookup` |
| S6 | Doychev et al., *CacheAudit: A Tool for the Static Analysis of Cache Side Channels* (USENIX Security 2013) | Analyzes programs with a cache configuration and adversaries observing cache states, hit/miss traces, and execution times. | Validation abstraction | Justifies trace-driven cache model and leakage-score style validation |
| S7 | Weiser et al., *DATA: Differential Address Trace Analysis* (USENIX Security 2018) | Uses address traces to detect address-based side channels, including cache-related leaks; also considers control-flow/data differences. | Victim address-trace abstraction | Supports address-trace generation and branch/code-footprint patterns |
| S8 | Wang et al., *Identifying Cache-Based Side Channels through Secret-Augmented Abstract Interpretation* / CacheS (USENIX Security 2019) | Frames cache leakage as revealing secrets by measuring cache access patterns, and analyzes real cryptographic implementations. | Secret-dependent cache access pattern | Supports our focus on victim access patterns rather than full attack reproduction |
| S9 | Almeida et al., *Verifying Constant-Time Implementations* (USENIX Security 2016) | Provides formal constant-time context and discusses secret-dependent memory access in cryptographic implementations. | Program-level mitigation principle | Constant-footprint defenses such as scan-all, balanced branch, fixed-count padding |
| S10 | Ma et al., *Quantifying and Mitigating Cache Side Channel Leakage with Differential Set* (OOPSLA 2023) | Uses secret-dependent cache footprints as the core abstraction and connects quantification with mitigation. | Program-level leakage/mitigation abstraction | Defense mapping; constant-footprint style mitigations |
| S11 | Zhou, Reiter, and Zhang, *A Software Approach to Defeating Side Channels in Last-Level Caches* / CacheBar (2016) | Discusses mitigating LLC access-driven side channels and thwarting cross-tenant Prime+Probe by managing cacheability/sharing. | System/cache-level mitigation | `table_lookup_partitioned_cache` |

---

## Extracted Victim Leakage Patterns

These are the vulnerable victim patterns we keep in `scenarios/llm_extracted_patterns.json`.

| Pattern | Main source motivation | Attack method fixed? | Simplified victim pattern | Why it is suitable for our simulator |
|---|---|---|---|---|
| `secret_dependent_table_lookup` | S1, S2 | Prime+Probe-style | `access(table_base + secret * line_size)` | The secret changes the cache set disturbed by the victim. |
| `multi_table_lookup_footprint` | S2, S3 | Prime+Probe-style | `for t in tables: access(table_base[t] + f(secret,t) * line_size)` | Models multiple table-like accesses creating a wider secret-dependent footprint. |
| `secret_dependent_branch_footprint` | S7, S8, S9, S10 | Prime+Probe-style | `if secret_bit: access(region_true) else: access(region_false)` | Different control-flow paths touch different cache-visible regions. |
| `secret_dependent_loop_count` | S7, S9, S10 | Prime+Probe-style | `for i in range(secret + 1): access(base + i * line_size)` | The number of disturbed sets depends on the secret. |
| `set_aliasing_table_lookup` | S3, S5, S6 | Prime+Probe-style | `access(table_base + secret * stride)` where multiple secrets map to the same cache set | Prime+Probe observes sets, not exact addresses, so leakage can be partial. |

---

## Defense / Mitigation Sources and Mapping

Defense scenarios are kept separately in `scenarios/defense_scenarios.json`. The defense comparison does not claim one universal defense implementation. Instead, it applies pattern-specific mitigations that share a common principle: **reduce or remove secret-dependent cache-visible behavior**.

| Defense / mitigation | Source motivation | Defense layer | Base leakage pattern | Scenario example |
|---|---|---|---|---|
| Constant-time table scan | S9, S10 | Program-level constant-footprint | Table lookup | `table_lookup_constant_time_scan` |
| Multi-table constant-time footprint | S9, S10 | Program-level constant-footprint | Multi-table lookup | `multi_table_constant_time_footprint` |
| Balanced branch footprint | S7, S9, S10 | Program-level constant-footprint/control-flow balancing | Branch footprint | `branch_balanced_footprint` |
| Fixed-count loop padding | S9, S10 | Program-level constant-work / constant-footprint | Loop count | `loop_count_fixed_count_padding` |
| Random padding | General noise/randomization mitigation idea; included as a weak comparison point, not a strong guarantee | Program-level noise/randomization | Table lookup | `table_lookup_random_padding` |
| Partitioned/isolated cache sets | S11 | System/cache-level isolation | Table lookup | `table_lookup_partitioned_cache` |

---

## Why This Makes the Project More Than a Teaching Demo

A pure teaching demo would manually define a few cache examples and show that some sets become slow. Our workflow is different:

1. Use literature to identify representative cache side-channel concepts.
2. Separate each concept into attacker observation method and victim leakage pattern.
3. Fix the attacker method to Prime+Probe-style observation for this prototype.
4. Convert victim leakage patterns into structured JSON scenarios.
5. Run each scenario through the same trace-driven simulator.
6. Evaluate leakage using secret prediction accuracy over random baseline.
7. Compare corresponding mitigation scenarios under the same validation pipeline.

This keeps the simulator as the validation backend, while the project focus is the **LLM/literature-guided security test generation workflow**.

---

## Current Boundary and Limitations

- We do not reproduce the full attacks in the papers.
- We do not implement real hardware measurement, eviction-set discovery, OS scheduling effects, prefetchers, TLBs, or out-of-order execution.
- We currently fix the observation model to Prime+Probe-style probing.
- We abstract source concepts into simplified victim address traces.
- Timing values are normalized simulator units, not calibrated CPU cycles.
- The goal is to validate **leakage potential in a controlled model**, not to prove real-world exploitability.

---

## References / Links

- Daniel J. Bernstein, *Cache-timing attacks on AES* (2005): https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
- Dag Arne Osvik, Adi Shamir, Eran Tromer, *Cache Attacks and Countermeasures: the Case of AES* (2005/2006): https://eprint.iacr.org/2005/271/
- Joseph Bonneau, Ilya Mironov, *Cache-Collision Timing Attacks Against AES* (CHES 2006): https://link.springer.com/chapter/10.1007/11894063_16
- Fangfei Liu, Yuval Yarom, Qian Ge, Gernot Heiser, Ruby B. Lee, *Last-Level Cache Side-Channel Attacks are Practical* (IEEE S&P 2015): https://trustworthy.systems/publications/nictaabstracts/Liu_YGHL_15.abstract
- Zirui Neil Zhao, Adam Morrison, Christopher W. Fletcher, Josep Torrellas, *Last-Level Cache Side-Channel Attacks Are Feasible in the Modern Public Cloud* (ASPLOS 2024): https://iacoma.cs.uiuc.edu/iacoma-papers/asplos24_2.pdf
- Goran Doychev et al., *CacheAudit: A Tool for the Static Analysis of Cache Side Channels* (USENIX Security 2013): https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/doychev
- Samuel Weiser et al., *DATA: Differential Address Trace Analysis: Finding Address-based Side-Channels in Binaries* (USENIX Security 2018): https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-weiser.pdf
- Shuai Wang et al., *Identifying Cache-Based Side Channels through Secret-Augmented Abstract Interpretation* (USENIX Security 2019): https://www.usenix.org/system/files/sec19-wang-shuai.pdf
- José Bacelar Almeida et al., *Verifying Constant-Time Implementations* (USENIX Security 2016): https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_almeida.pdf
- Cong Ma et al., *Quantifying and Mitigating Cache Side Channel Leakage with Differential Set* (OOPSLA 2023): https://mc-pony.com/assets/documents/DS.pdf
- Ziqiao Zhou, Michael K. Reiter, Yinqian Zhang, *A Software Approach to Defeating Side Channels in Last-Level Caches* / CacheBar (2016): https://arxiv.org/abs/1603.05615

---

## Step 2: LLM Extraction Prompt Layer

The prompt template in `prompts/llm_pattern_extraction_prompt.md` formalizes how we ask an LLM to convert curated paper excerpts or summaries into structured candidate patterns.

This is still **not** an automatic paper-ingestion system. The expected workflow is:

1. A human selects a representative source excerpt or summary.
2. The LLM applies the extraction prompt and returns structured candidates.
3. A human reviews whether each candidate is a vulnerable victim pattern, a mitigation candidate, only an attack observation method, or unsupported.
4. Only reviewed, simulator-compatible scenarios are copied into `scenarios/llm_extracted_patterns.json` or `scenarios/defense_scenarios.json`.

This keeps the project claim conservative: we use LLM-assisted literature abstraction to generate candidate security tests, and the simulator validates those tests in a simplified Prime+Probe-style timing model.

---

## Step 3: From Raw LLM Candidates to Reviewed Scenarios

The project now includes a documented review layer under `llm_outputs/`:

```text
curated source concept / paper excerpt
        ↓
LLM extraction prompt
        ↓
raw_llm_patterns.json
        ↓
human/schema review
        ↓
reviewed_patterns.json
        ↓
executable scenario files
```

This is still **not** automatic PDF ingestion. The raw LLM candidate file is a recorded, structured representation of what the LLM-assisted extraction step is expected to produce. The reviewed file documents human decisions that keep the project logically consistent:

- vulnerable victim leakage patterns enter `scenarios/llm_extracted_patterns.json`;
- mitigation candidates enter `scenarios/defense_scenarios.json`;
- attack observation methods such as Prime+Probe are kept as methodology notes;
- unsupported concepts such as transient/speculative execution are rejected for the current prototype.

This keeps the simulator backend focused on executable Prime+Probe-style validation while still showing how literature concepts are converted into testable scenarios.
