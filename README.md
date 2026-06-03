# LLM-Assisted Cache Leakage Pattern Analysis

This project is a controlled prototype for **LLM-assisted cache leakage pattern analysis and simulator-based validation**.

The goal is **not** to implement a real hardware attack. The goal is to show a safe workflow where LLM/paper-inspired victim leakage patterns are reviewed, encoded as executable JSON scenarios, and validated in a simplified Prime+Probe-style cache timing simulator.

## Core idea

```text
curated cache side-channel literature / notes
    -> LLM-style candidate pattern generation
    -> human/schema review
    -> executable JSON scenarios
    -> Prime+Probe-style trace-driven simulator
    -> leakage evaluator and validation report
```

## Important scope

- The attacker observation method is fixed as **Prime+Probe-style observation**.
- The project compares **victim program leakage patterns**, not multiple attack methods.
- Raw LLM candidates are **not executed directly**.
- The executable inputs are the reviewed scenario files under `scenarios/`.
- Timing uses normalized simulator units, not hardware-calibrated CPU cycle counts.

## File roles

### Files used by the main program

```text
main.py
    Runs all experiments and generates CSV results, plots, and the validation report.

scenarios/llm_extracted_patterns.json
    Executable vulnerable victim leakage patterns.
    Used by pattern comparison, noise sweep, and partial leakage analysis.

scenarios/defense_scenarios.json
    Executable no-defense and mitigation scenarios.
    Used by defense comparison and defense noise sweep.

src/cache_model.py
    Set-associative cache model: set/tag mapping, ways, LRU, hit/miss latency, noise.

src/victim_patterns.py
    Converts scenario pattern types into victim address traces.

src/trace_generator.py
    Runs the Prime+Probe-style flow: attacker prime -> victim run -> attacker probe.

src/leakage_evaluator.py
    Uses nearest-mean classification to test whether timing vectors reveal the secret.

src/experiments.py
    Runs pattern, noise, defense, defense-noise, and partial-leakage experiments.

src/plotting.py
    Generates result plots and confusion matrix plots.

src/reporting.py
    Generates the Markdown validation report from results and reviewed patterns.
```

### LLM / literature workflow files

These files support the project methodology but are **not directly executed by `main.py`**:

```text
literature/paper_sources.md
    Literature grounding and source-to-pattern rationale.

prompts/llm_pattern_extraction_prompt.md
    Prompt template for asking an LLM to extract structured candidate patterns.

schemas/llm_pattern_candidate_schema.json
    Schema describing what a raw LLM candidate output should contain.

llm_outputs/raw_llm_patterns.json
    LLM-style raw candidate patterns. These may include unsupported or misclassified ideas.

llm_outputs/reviewed_patterns.json
    Human/schema review record showing which raw candidates were accepted, rejected, or moved.

llm_outputs/pattern_review_report.csv
    Compact review summary.

scripts/check_step3_consistency.py
    Optional consistency check between raw/reviewed outputs and executable scenario JSON files.
```

A useful short rule is:

```text
schema JSON   = format rule
raw JSON      = LLM draft candidates
reviewed JSON = human review record
scenarios JSON = executable experiment input
```

## Experiments

Running `python main.py` generates:

```text
results/pattern_results.csv
plots/pattern_leakage_comparison.png

results/noise_sweep.csv
plots/noise_sweep.png

results/defense_results.csv
plots/defense_comparison.png

results/defense_noise_sweep.csv
plots/defense_noise_sweep.png

results/partial_leakage_summary.csv
results/confusion_matrix_*.csv
plots/confusion_matrix_*.png

results/pattern_validation_report.md
```

The experiments are:

1. **Vulnerable pattern comparison**: compares accepted victim leakage patterns.
2. **Noise sensitivity**: varies timing noise for vulnerable patterns.
3. **Defense comparison**: compares no-defense baselines with program-level and system-level mitigations.
4. **Defense noise sweep**: tests table-lookup mitigations under increasing timing noise.
5. **Partial leakage analysis**: uses confusion matrices and group accuracy to show leakage of coarser secret groups.

## How to run

```bash
python main.py
```

Optional consistency check:

```bash
python scripts/check_step3_consistency.py
```

Debug one expanded trial:

```bash
python debug_trial.py --pattern secret_dependent_table_lookup --secret 3
```

For a defense scenario:

```bash
python debug_trial.py --scenario-file scenarios/defense_scenarios.json --pattern table_lookup_partitioned_cache --secret 3
```

## Limitations

This prototype shows leakage potential in a simplified model. It does not prove real-world exploitability. It does not automatically read PDFs, does not execute raw LLM outputs directly, and does not model full hardware behavior such as multi-level caches, prefetching, OS scheduling, branch prediction, transient execution, or real eviction-set discovery.
