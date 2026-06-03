# LLM Outputs

This folder documents the LLM-assisted pattern generation layer.

The current prototype does **not** automatically read PDFs, crawl paper links, or call an LLM API during `python main.py`.
Instead, it uses a curated workflow:

```text
representative paper concepts / excerpts
        ↓
LLM extraction prompt
        ↓
raw structured candidate patterns
        ↓
human/schema review
        ↓
executable JSON scenarios
        ↓
simulator validation
```

## Files

- `raw_llm_patterns.json`
  - Representative raw LLM-style candidate output.
  - Contains accepted victim leakage patterns, mitigation candidates, attack-method-only concepts, and rejected out-of-scope ideas.

- `reviewed_patterns.json`
  - Human-reviewed mapping from raw candidates to executable scenario files.
  - Clarifies which candidates go to `scenarios/llm_extracted_patterns.json`, which go to `scenarios/defense_scenarios.json`, and which are only documented or rejected.

- `pattern_review_report.csv`
  - Compact review summary used for reporting/presentation.

- `step3_review_notes.md`
  - Plain-English explanation of the Step 3 workflow and scope boundaries.

## Important scope rule

`scenarios/llm_extracted_patterns.json` contains only vulnerable victim leakage patterns.
Defense or mitigation candidates belong in `scenarios/defense_scenarios.json`.
Attack observation methods such as Prime+Probe are not victim program patterns; in this project Prime+Probe is the fixed observation model.
