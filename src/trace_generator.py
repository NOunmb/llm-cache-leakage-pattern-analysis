"""Prime+Probe-style trace generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Literal, Sequence
import inspect
import random

from .cache_model import CacheConfig, SetAssociativeCache, address_for_set

VictimTraceBuilder = Callable[..., List[int]]
ProbeOrder = Literal["forward", "reverse"]


@dataclass
class TrialResult:
    secret: int
    victim_trace: List[int]
    timing_vector: List[float]


def validate_monitored_sets(config: CacheConfig, monitored_sets: Sequence[int] | None) -> list[int]:
    """Validate and normalize the attacker-monitored cache sets.

    ``None`` means the attacker monitors every set. Otherwise, every set index
    must be an integer in ``[0, num_sets - 1]`` and duplicates are rejected.
    """
    if monitored_sets is None:
        return list(range(config.num_sets))
    normalized = list(monitored_sets)
    if not normalized:
        raise ValueError("monitored_sets must not be empty")
    if not all(isinstance(set_index, int) for set_index in normalized):
        raise ValueError("monitored_sets must contain only integers")
    invalid = [set_index for set_index in normalized if not 0 <= set_index < config.num_sets]
    if invalid:
        raise ValueError(f"monitored_sets contains out-of-range set index values: {invalid}")
    if len(set(normalized)) != len(normalized):
        raise ValueError("monitored_sets must not contain duplicate set indexes")
    return normalized


def build_attacker_addresses(config: CacheConfig, monitored_sets: Sequence[int] | None = None, base_tag: int = 100) -> List[List[int]]:
    """Build one attacker eviction set per monitored cache set.

    For a W-way cache, the attacker uses W addresses mapping to the same set but
    different tags, so priming fills that set with attacker-owned lines.
    """
    normalized_sets = validate_monitored_sets(config, monitored_sets)

    attacker_addresses: List[List[int]] = []
    for set_index in normalized_sets:
        per_set = [address_for_set(set_index, base_tag + way, config) for way in range(config.ways)]
        attacker_addresses.append(per_set)
    return attacker_addresses


def _call_victim_builder(
    victim_builder: VictimTraceBuilder,
    secret: int,
    config: CacheConfig,
    secret_space: int,
    rng: random.Random,
) -> List[int]:
    """Call a victim builder while passing rng only when accepted."""
    signature = inspect.signature(victim_builder)
    accepts_rng = (
        "rng" in signature.parameters
        or any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values())
    )
    kwargs = {"secret_space": secret_space}
    if accepts_rng:
        kwargs["rng"] = rng
    return victim_builder(secret, config, **kwargs)


def run_single_trial(
    secret: int,
    cache: SetAssociativeCache,
    victim_builder: VictimTraceBuilder,
    secret_space: int,
    attacker_addresses: List[List[int]],
    rng: random.Random,
    probe_order: ProbeOrder = "reverse",
) -> TrialResult:
    """Run one simplified Prime+Probe-style trial."""
    cache.reset()

    # 1. Attacker prime: fill monitored sets with attacker lines.
    for per_set in attacker_addresses:
        for address in per_set:
            cache.access(address)

    # 2. Victim runs: access pattern depends on the selected scenario.
    victim_trace = _call_victim_builder(victim_builder, secret, cache.config, secret_space, rng)

    for address in victim_trace:
        cache.access(address)

    # 3. Attacker probe: measure aggregate probe time per monitored set.
    # Reverse order avoids self-evicting the remaining attacker line in this
    # simple 2-way model, so one victim eviction usually appears as one hit +
    # one miss instead of two misses. The probe is still a real cache access and
    # still updates cache state.
    if probe_order not in ("forward", "reverse"):
        raise ValueError("probe_order must be 'forward' or 'reverse'")

    timing_vector: List[float] = []
    for per_set in attacker_addresses:
        probe_sequence = per_set if probe_order == "forward" else list(reversed(per_set))
        total = 0.0
        for address in probe_sequence:
            total += cache.access(address).latency
        timing_vector.append(total)

    return TrialResult(secret=secret, victim_trace=victim_trace, timing_vector=timing_vector)


def generate_dataset(
    victim_builder: VictimTraceBuilder,
    config: CacheConfig,
    n_trials: int = 1000,
    secret_space: int = 4,
    seed: int = 7,
    probe_order: ProbeOrder = "reverse",
    monitored_sets: Sequence[int] | None = None,
) -> tuple[list[list[float]], list[int]]:
    """Generate timing vectors X and true secrets y."""
    rng = random.Random(seed)
    cache = SetAssociativeCache(config=config, rng=rng)
    attacker_addresses = build_attacker_addresses(config, monitored_sets=monitored_sets)

    X: list[list[float]] = []
    y: list[int] = []
    for _ in range(n_trials):
        secret = rng.randrange(secret_space)
        result = run_single_trial(
            secret=secret,
            cache=cache,
            victim_builder=victim_builder,
            secret_space=secret_space,
            attacker_addresses=attacker_addresses,
            rng=rng,
            probe_order=probe_order,
        )
        X.append(result.timing_vector)
        y.append(secret)
    return X, y
