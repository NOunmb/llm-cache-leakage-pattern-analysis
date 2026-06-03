"""Victim memory-access patterns.

Each function converts a secret into an address trace. The simulator, not the
victim pattern itself, decides which cache sets are disturbed.

Milestone 2 adds a config-driven layer: a JSON scenario specifies the pattern
name/type and parameters, and this module turns that scenario into an executable
victim trace builder.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List
import inspect
import random

from .cache_model import CacheConfig, address_for_set

Scenario = Dict[str, Any]
VictimTraceBuilder = Callable[..., List[int]]


def table_lookup_trace(secret: int, config: CacheConfig, secret_space: int = 4, victim_tag: int = 10) -> List[int]:
    """Secret-dependent table lookup.

    Different secret values touch different cache sets. This should leak in a
    Prime+Probe-style simplified model because the disturbed set depends on the
    secret.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    set_index = secret % config.num_sets
    return [address_for_set(set_index=set_index, tag=victim_tag, config=config)]


def constant_time_scan_trace(secret: int, config: CacheConfig, secret_space: int = 4, victim_tag: int = 10) -> List[int]:
    """Constant-time scan.

    The victim touches every candidate location regardless of the secret. This
    should reduce leakage because the trace is almost the same for every secret.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    return [address_for_set(set_index=i % config.num_sets, tag=victim_tag, config=config) for i in range(secret_space)]


def loop_count_trace(secret: int, config: CacheConfig, secret_space: int = 4, victim_tag: int = 10) -> List[int]:
    """Secret-dependent loop count.

    A larger secret causes more memory locations to be touched. This can leak
    through the number of disturbed sets.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    return [address_for_set(set_index=i % config.num_sets, tag=victim_tag, config=config) for i in range(secret + 1)]


def random_padding_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 4,
    victim_tag: int = 10,
    padding_count: int = 3,
    rng: random.Random | None = None,
) -> List[int]:
    """Table lookup plus random extra accesses.

    This may reduce leakage by adding noisy disturbances, but it is not a
    reliable constant-time defense because the secret-dependent access remains.
    """
    if rng is None:
        rng = random.Random()
    trace = table_lookup_trace(secret, config, secret_space, victim_tag)
    for _ in range(padding_count):
        random_set = rng.randrange(config.num_sets)
        random_tag = victim_tag + 1 + rng.randrange(50)
        trace.append(address_for_set(random_set, random_tag, config))
    return trace


def multi_table_lookup_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 4,
    victim_tag: int = 10,
    num_tables: int = 4,
    table_set_stride: int = 1,
) -> List[int]:
    """Secret-dependent multi-table lookup.

    This models table-driven implementations where one secret-dependent value
    causes several table-like memory accesses. Each access maps to a related
    cache set, producing a wider memory-access footprint than a single lookup.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    trace: List[int] = []
    for table_id in range(num_tables):
        set_index = (secret + table_id * table_set_stride) % config.num_sets
        trace.append(address_for_set(set_index=set_index, tag=victim_tag + table_id, config=config))
    return trace


def secret_dependent_branch_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 4,
    victim_tag: int = 10,
    false_set: int = 1,
    true_set: int = 5,
) -> List[int]:
    """Secret-dependent branch / code-path footprint.

    This models a victim that branches on one secret bit. The attacker may learn
    which branch footprint was touched, but this reveals only partial secret
    information when the secret space has more than two values.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    set_index = true_set if (secret & 1) else false_set
    return [address_for_set(set_index=set_index % config.num_sets, tag=victim_tag, config=config)]


def set_aliasing_lookup_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 8,
    victim_tag: int = 10,
    alias_sets: int = 4,
) -> List[int]:
    """Secret-dependent lookup with cache-set aliasing.

    Different secrets access different logical entries, but the attacker observes
    only cache-set-level disturbances. If multiple logical entries map to the
    same observed set, the timing trace leaks partial information but cannot
    distinguish all secret values.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    if alias_sets <= 0 or alias_sets > config.num_sets:
        raise ValueError("alias_sets must be between 1 and num_sets")
    set_index = secret % alias_sets
    # Use a secret-dependent tag so the logical memory entry is different even
    # when two secrets alias to the same observed set. Prime+Probe observes the
    # set disturbance, not the exact tag.
    return [address_for_set(set_index=set_index, tag=victim_tag + secret, config=config)]


def balanced_branch_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 4,
    victim_tag: int = 10,
    false_set: int = 1,
    true_set: int = 5,
) -> List[int]:
    """Balanced branch/code-path footprint.

    This is a program-level mitigation for secret-dependent branch footprints.
    Instead of touching only the branch selected by the secret bit, the victim
    touches both branch regions in a fixed order. The resulting cache footprint
    is independent of the secret.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    return [
        address_for_set(set_index=false_set % config.num_sets, tag=victim_tag, config=config),
        address_for_set(set_index=true_set % config.num_sets, tag=victim_tag, config=config),
    ]


def fixed_loop_count_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 4,
    victim_tag: int = 10,
    fixed_count: int | None = None,
) -> List[int]:
    """Fixed-loop-count mitigation for secret-dependent loop count.

    The vulnerable loop_count pattern touches secret + 1 locations. This
    mitigation always touches a fixed number of locations, independent of the
    secret. By default the fixed count is the full secret space.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    count = secret_space if fixed_count is None else int(fixed_count)
    return [address_for_set(set_index=i % config.num_sets, tag=victim_tag, config=config) for i in range(count)]


def multi_table_constant_time_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 4,
    victim_tag: int = 20,
    num_tables: int = 4,
    table_set_stride: int = 1,
) -> List[int]:
    """Constant-time mitigation for multi-table lookup footprints.

    The vulnerable multi-table lookup touches entries derived from the actual
    secret. This mitigation touches the table footprint for every candidate
    secret in a fixed order, so the overall trace is independent of the real
    secret.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    trace: List[int] = []
    for candidate in range(secret_space):
        for table_id in range(num_tables):
            set_index = (candidate + table_id * table_set_stride) % config.num_sets
            tag = victim_tag + table_id * secret_space + candidate
            trace.append(address_for_set(set_index=set_index, tag=tag, config=config))
    return trace


def partitioned_cache_trace(
    secret: int,
    config: CacheConfig,
    secret_space: int = 4,
    victim_tag: int = 10,
    victim_set_offset: int = 4,
) -> List[int]:
    """Secret-dependent lookup placed outside the attacker's monitored sets.

    This is a simplified cache-partitioning-style mitigation. The victim still
    accesses a secret-dependent location, but that location is intentionally
    mapped to a cache-set region that the attacker does not monitor. In the
    default defense scenario, the attacker monitors sets 0-3 while the victim
    uses sets 4-7.
    """
    if not 0 <= secret < secret_space:
        raise ValueError("secret out of range")
    set_index = (victim_set_offset + secret) % config.num_sets
    return [address_for_set(set_index=set_index, tag=victim_tag, config=config)]


# Maps config pattern_type values to implementation functions.
PATTERN_BUILDERS: dict[str, VictimTraceBuilder] = {
    "table_lookup": table_lookup_trace,
    "constant_time_scan": constant_time_scan_trace,
    "loop_count": loop_count_trace,
    "random_padding": random_padding_trace,
    "multi_table_lookup": multi_table_lookup_trace,
    "secret_dependent_branch": secret_dependent_branch_trace,
    "set_aliasing_lookup": set_aliasing_lookup_trace,
    "balanced_branch": balanced_branch_trace,
    "fixed_loop_count": fixed_loop_count_trace,
    "multi_table_constant_time": multi_table_constant_time_trace,
    "partitioned_cache": partitioned_cache_trace,
    # Backward-compatible names from Milestone 1.
    "secret_dependent_table_lookup": table_lookup_trace,
    "secret_dependent_loop_count": loop_count_trace,
}


def _call_builder_with_optional_rng(
    builder: VictimTraceBuilder,
    secret: int,
    config: CacheConfig,
    secret_space: int,
    rng: random.Random | None,
    params: dict[str, Any] | None = None,
) -> List[int]:
    """Call a victim builder, passing rng only when the builder accepts it.

    This avoids a broad ``except TypeError`` fallback. A real TypeError inside a
    pattern function should surface immediately instead of being mistaken for
    an unsupported ``rng`` argument.
    """
    params = {} if params is None else params
    signature = inspect.signature(builder)
    accepts_rng = (
        "rng" in signature.parameters
        or any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values())
    )
    kwargs: dict[str, Any] = {"secret_space": secret_space, **params}
    if accepts_rng:
        kwargs["rng"] = rng
    return builder(secret, config, **kwargs)


def build_victim_builder_from_scenario(scenario: Scenario) -> VictimTraceBuilder:
    """Create a victim trace builder from one JSON scenario.

    The returned builder has the same call style expected by trace_generator:
    builder(secret, config, secret_space=..., rng=...). Scenario parameters are
    passed into the selected pattern function.
    """
    pattern_type = scenario["pattern_type"]
    if pattern_type not in PATTERN_BUILDERS:
        supported = ", ".join(sorted(PATTERN_BUILDERS))
        raise ValueError(f"Unsupported pattern_type '{pattern_type}'. Supported: {supported}")

    base_builder = PATTERN_BUILDERS[pattern_type]
    scenario_secret_space = int(scenario.get("secret_space", 4))
    params = dict(scenario.get("parameters", {}))

    def scenario_builder(
        secret: int,
        config: CacheConfig,
        secret_space: int = scenario_secret_space,
        rng: random.Random | None = None,
    ) -> List[int]:
        # The scenario's secret_space is the source of truth for this test case.
        return _call_builder_with_optional_rng(
            builder=base_builder,
            secret=secret,
            config=config,
            secret_space=scenario_secret_space,
            rng=rng,
            params=params,
        )

    return scenario_builder
