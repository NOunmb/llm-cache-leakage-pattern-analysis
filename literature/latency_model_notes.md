# Latency Model Notes

## Current decision

This prototype keeps the cache timing model as **normalized simulator timing units**:

- cache hit latency: `10.0`
- cache miss latency: `30.0`
- timing noise: additive Gaussian noise controlled by `noise_std`

We intentionally do **not** claim these values are calibrated to a specific CPU, cache level, or microarchitecture.

## Why we did not replace the latency constants with paper-specific values

Published cache timing values depend heavily on the processor, cache level, memory hierarchy, measurement method, operating system noise, and whether the experiment is measuring L1, LLC, DRAM, or an end-to-end side-channel timing signal. Directly copying one paper's reported timing numbers into this simplified simulator could make the model look more realistic than it actually is.

For the current project, the important controlled variable is the **hit/miss timing gap**, not the exact cycle count. The normalized values keep the model easy to explain:

- unaffected 2-way monitored set: `hit + hit = 20`
- affected 2-way monitored set: `hit + miss = 40`

This makes the simulator useful as a validation backend for comparing LLM/paper-inspired victim patterns under the same assumptions.

## How timing uncertainty is modeled

Each cache access latency is computed as:

```text
latency = base_hit_or_miss_latency + Gaussian noise
```

The noise sweep varies `noise_std` to test whether leakage remains detectable as timing measurements become less stable.

## Future work

A more realistic version could add hardware-calibrated timing profiles, for example:

- separate L1/L2/LLC/DRAM latencies;
- architecture-specific latency profiles;
- empirically measured timing distributions;
- non-Gaussian noise and OS scheduling effects;
- prefetching and replacement-policy variations.

For the current prototype, we keep the normalized model and explicitly state this limitation in the validation report.
