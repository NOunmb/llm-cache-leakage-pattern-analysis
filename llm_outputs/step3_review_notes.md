# Step 3: Raw LLM Candidates and Human Review

This directory documents the intermediate layer between literature concepts and executable simulator scenarios.

## What this step adds

Step 1 created `literature/paper_sources.md`, which grounds the project in representative cache side-channel concepts.
Step 2 created `prompts/llm_pattern_extraction_prompt.md`, which defines how an LLM should extract structured candidates from curated paper text or notes.
Step 3 records the next stage:

```text
curated paper concept / excerpt
        ↓
LLM-style structured candidate output
        ↓
human/schema review
        ↓
executable scenario files
```

The current prototype does **not** automatically read PDFs or call an LLM API. The files here are a documented, reproducible representation of the candidate-generation and review workflow.

## Files

- `raw_llm_patterns.json`
  - Records representative raw LLM-style candidate outputs.
  - Includes accepted vulnerable victim patterns, accepted mitigation candidates, attack-method-only concepts, and rejected out-of-scope concepts.

- `reviewed_patterns.json`
  - Records how each raw candidate was reviewed.
  - Explains which candidates enter `scenarios/llm_extracted_patterns.json`, which enter `scenarios/defense_scenarios.json`, which are only kept in literature notes, and which are rejected.

- `pattern_review_report.csv`
  - Compact tabular review summary for presentation/report use.

## Important separation

`llm_extracted_patterns.json` should contain only vulnerable victim leakage patterns.
Mitigation candidates belong in `defense_scenarios.json`.
Attack observation methods such as Prime+Probe or Flush+Reload are not victim program patterns.

The current simulator fixes the attacker observation method as Prime+Probe-style and validates simulator-compatible victim memory-access patterns.
