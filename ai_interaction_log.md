# AI Interaction Log

This file summarizes how the LLM is used in the project workflow.

## Round 1: Project scoping

Prompt idea: Design a safe AI-assisted security project related to cache side-channel leakage.

AI output: Suggested a controlled simulator-based workflow instead of a real hardware exploit.

Human decision: Use a simplified trace-driven cache simulator to avoid overclaiming real-world attack success.

## Round 2: Pattern abstraction

Prompt idea: Summarize common cache side-channel attack/defense concepts and convert them into bounded victim memory-access patterns.

AI output: Identified patterns such as secret-dependent table lookup, secret-dependent loop count, constant-time access, and random padding.

Human decision: Use these as representative test scenarios rather than claiming full attack coverage.

## Round 3: Config-driven test cases

Prompt idea: Convert the selected concepts into a compact JSON scenario format.

AI output: Produced scenario fields such as name, pattern_type, secret_space, expected_leakage, source_inspiration, and parameters.

Human decision: Store the selected scenarios in `scenarios/llm_extracted_patterns.json` and use the simulator to validate whether each pattern leaks.

## Round 4: Validation rule

Prompt idea: How should leakage be measured in the simplified simulator?

AI output: Suggested using timing vectors and a nearest-mean classifier to predict the secret above random baseline.

Human decision: Use prediction accuracy over random baseline as the prototype leakage metric.
