# LLM Pattern Extraction Prompt

This prompt is used for the **LLM-assisted literature abstraction layer** of the project. It is not an automatic PDF-ingestion pipeline. A human provides a paper excerpt, paper summary, or curated notes, and the LLM returns structured candidate patterns. A human then reviews the output before any candidate is copied into `scenarios/llm_extracted_patterns.json` or `scenarios/defense_scenarios.json`.

## Purpose

The goal is to convert representative cache side-channel literature concepts into **simulator-compatible victim program patterns**. The current prototype fixes the attack observation method as **Prime+Probe-style observation**, so the LLM should focus on the victim-side behavior that creates a cache-visible footprint.

The LLM must separate:

1. **Attack observation method** — how the attacker observes cache state, such as Prime+Probe, Flush+Reload, Evict+Time, or Flush+Flush.
2. **Victim program leakage pattern** — what victim memory-access or control-flow behavior makes the cache footprint depend on a secret.
3. **Mitigation / defense idea** — how the victim or system reduces secret-dependent cache-visible behavior.

Only victim leakage patterns and mitigation ideas that can be reduced to address traces should be considered for this simulator.

---

## Prompt Template

Use the following prompt when asking an LLM to extract candidate patterns from a paper excerpt or curated paper notes.

```text
You are helping build a controlled educational/research prototype for LLM-guided cache side-channel leakage testing.

Important scope limits:
- Do NOT generate real exploit instructions or hardware attack procedures.
- Do NOT claim real-world exploit success.
- Do NOT design a new real attack.
- The prototype fixes the attacker observation method as Prime+Probe-style cache-set timing observation.
- Your task is to extract victim-side leakage patterns or mitigation ideas that can be represented as simplified address traces.

Input:
[Paste a paper excerpt, paper summary, or curated notes here.]

Task:
Read the input and identify candidate concepts that could become simulator scenarios.
For each candidate, separate the attack observation method from the victim program behavior.
Classify each candidate as one of:
1. vulnerable_victim_pattern
2. mitigation_candidate
3. attack_observation_method_only
4. unsupported_or_out_of_scope

Supported executable pattern types in the current simulator are:
- table_lookup
- multi_table_lookup
- secret_dependent_branch
- loop_count
- set_aliasing_lookup
- constant_time_scan
- random_padding
- balanced_branch
- fixed_loop_count
- multi_table_constant_time
- partitioned_cache

Rules:
- If the paper only describes an attack method, such as Prime+Probe or Flush+Reload, do not treat that as a victim pattern.
- If the idea is a vulnerable victim behavior, prefer one of: table_lookup, multi_table_lookup, secret_dependent_branch, loop_count, set_aliasing_lookup.
- If the idea is a defense or mitigation, prefer one of: constant_time_scan, random_padding, balanced_branch, fixed_loop_count, multi_table_constant_time, partitioned_cache.
- If no supported pattern type fits, mark simulator_support as unsupported and explain why.
- Keep the pseudocode simplified and safe. It should describe abstract memory accesses only, not exploit steps.
- Be conservative. If the source does not support a claim, say so.

Return ONLY valid JSON using this structure:

{
  "source_id": "short identifier, e.g., S2",
  "source_title": "paper or source title",
  "candidates": [
    {
      "candidate_id": "short unique id",
      "classification": "vulnerable_victim_pattern | mitigation_candidate | attack_observation_method_only | unsupported_or_out_of_scope",
      "attack_method_layer": "Prime+Probe | Flush+Reload | Evict+Time | Flush+Flush | general cache timing | unclear | not_applicable",
      "victim_pattern_layer": "brief description of victim-side behavior, or null if not applicable",
      "mitigation_layer": "brief description if this is a mitigation, otherwise null",
      "supported_pattern_type": "one supported pattern_type or null",
      "simulator_support": "supported | needs_review | unsupported",
      "secret_space_suggestion": 4,
      "expected_leakage": "high | medium | low | unknown",
      "simplified_pseudocode": "safe abstract pseudocode, or null",
      "parameter_suggestions": {},
      "evidence_from_input": "brief non-quoted summary of what in the input supports this candidate",
      "why_this_fits_prime_probe_simulator": "brief explanation, or null",
      "limitations": "what this simplified scenario does not model",
      "recommended_destination": "llm_extracted_patterns.json | defense_scenarios.json | paper_sources_only | reject"
    }
  ]
}
```

---

## Review Rules After LLM Output

The raw LLM output should not be copied directly into executable scenario files. Review it using these rules:

1. **Layer check**
   - If a candidate is only an attack method, keep it in literature notes but do not put it in `llm_extracted_patterns.json`.
   - Example: Prime+Probe itself is an observation method, not a victim pattern.

2. **Destination check**
   - `llm_extracted_patterns.json` should contain only vulnerable victim leakage patterns.
   - `defense_scenarios.json` should contain no-defense controls and mitigation/defense scenarios.

3. **Simulator support check**
   - Use only supported `pattern_type` values.
   - If the LLM proposes a new pattern type, either map it to an existing supported type or mark it unsupported.

4. **Safety and scope check**
   - Keep only abstract address-trace scenarios.
   - Do not include real exploitation steps, target-specific instructions, or hardware attack procedures.

5. **Claim check**
   - The simulator validates leakage potential in a simplified model.
   - Do not claim real hardware validation.

---

## Example Interpretation

If a paper discusses AES table lookups whose memory locations depend on secret-derived values, the LLM may output a vulnerable victim pattern:

```json
{
  "classification": "vulnerable_victim_pattern",
  "attack_method_layer": "general cache timing",
  "victim_pattern_layer": "secret-dependent table lookup",
  "supported_pattern_type": "table_lookup",
  "simulator_support": "supported",
  "expected_leakage": "high",
  "simplified_pseudocode": "access(table_base + secret * line_size)",
  "recommended_destination": "llm_extracted_patterns.json"
}
```

If a paper discusses constant-time implementation principles, the LLM should not put that in the vulnerable pattern list. It should classify it as a mitigation candidate:

```json
{
  "classification": "mitigation_candidate",
  "victim_pattern_layer": null,
  "mitigation_layer": "make memory-access footprint independent of secret",
  "supported_pattern_type": "constant_time_scan",
  "simulator_support": "supported",
  "expected_leakage": "low",
  "simplified_pseudocode": "for i in range(secret_space): access(table_base + i * line_size)",
  "recommended_destination": "defense_scenarios.json"
}
```
