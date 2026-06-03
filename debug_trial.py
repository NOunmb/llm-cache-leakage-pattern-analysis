"""Print one fully expanded Prime+Probe-style trial.

This file is for understanding and sanity-checking the simulator. It does not
change the main experiment pipeline. It shows how a selected JSON scenario turns
into victim memory accesses, cache set/tag mappings, probe hit/miss events, and
the final timing vector.

Example:
    python debug_trial.py --pattern secret_dependent_table_lookup --secret 2
"""

from __future__ import annotations

import argparse
import random
from copy import deepcopy
from pathlib import Path
from typing import Iterable

from src.cache_model import CacheConfig, SetAssociativeCache
from src.scenario_loader import load_scenarios
from src.trace_generator import build_attacker_addresses, validate_monitored_sets
from src.victim_patterns import build_victim_builder_from_scenario


def format_tag_list(tags: Iterable[int]) -> str:
    tags = list(tags)
    if not tags:
        return "[]"
    return "[" + ", ".join(str(tag) for tag in tags) + "]"


def print_cache_state(title: str, cache: SetAssociativeCache) -> None:
    print(f"\n{title}")
    print("  Note: each set is ordered [LRU ... MRU].")
    for set_index, tags in enumerate(cache.sets):
        print(f"  set {set_index}: {format_tag_list(tags)}")


def find_scenario(scenarios: list[dict], pattern_name: str) -> dict:
    for scenario in scenarios:
        if scenario["name"] == pattern_name or scenario["pattern_type"] == pattern_name:
            return scenario
    names = ", ".join(s["name"] for s in scenarios)
    raise ValueError(f"Pattern '{pattern_name}' not found. Available scenario names: {names}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Show one expanded cache side-channel simulation trial.")
    parser.add_argument("--pattern", default="secret_dependent_table_lookup", help="Scenario name or pattern_type")
    parser.add_argument("--secret", type=int, default=2, help="Secret value to test")
    parser.add_argument("--seed", type=int, default=7, help="Random seed")
    parser.add_argument("--noise-std", type=float, default=0.0, help="Use 0 for clean hit/miss timing")
    parser.add_argument(
        "--probe-order",
        choices=["reverse", "forward"],
        default="reverse",
        help="reverse gives a clearer one-eviction = one hit + one miss view; forward keeps the old self-evicting order",
    )
    parser.add_argument("--scenario-file", default="scenarios/llm_extracted_patterns.json")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    scenario_path = root / args.scenario_file
    scenarios = load_scenarios(scenario_path)
    scenario = find_scenario(scenarios, args.pattern)

    secret_space = int(scenario.get("secret_space", 4))
    if not 0 <= args.secret < secret_space:
        raise ValueError(f"secret must be in [0, {secret_space - 1}] for this scenario")

    config = CacheConfig(
        num_sets=8,
        ways=2,
        line_size=64,
        hit_latency=10.0,
        miss_latency=30.0,
        noise_std=args.noise_std,
    )
    rng = random.Random(args.seed)
    cache = SetAssociativeCache(config=config, rng=rng)
    victim_builder = build_victim_builder_from_scenario(scenario)
    raw_monitored_sets = scenario.get("monitored_sets")
    monitored_sets = None if raw_monitored_sets is None else validate_monitored_sets(config, raw_monitored_sets)
    attacker_addresses = build_attacker_addresses(config, monitored_sets=monitored_sets)

    print("=== Debug single trial ===")
    print(f"Scenario name:      {scenario['name']}")
    print(f"Pattern type:       {scenario['pattern_type']}")
    print(f"Expected leakage:   {scenario['expected_leakage']}")
    print(f"Secret space:       {secret_space}")
    print(f"Chosen secret:      {args.secret}")
    print(f"Cache config:       sets={config.num_sets}, ways={config.ways}, line_size={config.line_size}")
    print(f"Timing config:      hit={config.hit_latency}, miss={config.miss_latency}, noise_std={config.noise_std}")
    print(f"Probe order:        {args.probe_order}")
    print(f"Monitored sets:     {monitored_sets if monitored_sets is not None else 'all'}")

    # 1. Prime
    cache.reset()
    print("\n--- Step 1: Attacker prime ---")
    monitored_labels = validate_monitored_sets(config, monitored_sets)
    for logical_index, per_set in enumerate(attacker_addresses):
        set_index = monitored_labels[logical_index]
        for address in per_set:
            result = cache.access(address)
            print(
                f"  prime set {set_index}: addr=0x{address:x}, "
                f"maps_to=(set={result.set_index}, tag={result.tag}), "
                f"{'hit' if result.hit else 'miss'}, latency={result.latency:.1f}"
            )
    print_cache_state("Cache state after prime:", cache)

    # 2. Victim run
    print("\n--- Step 2: Victim run ---")
    victim_trace = victim_builder(args.secret, cache.config, secret_space=secret_space, rng=rng)
    if not victim_trace:
        print("  victim trace is empty")
    for i, address in enumerate(victim_trace):
        before = deepcopy(cache.sets)
        result = cache.access(address)
        after = cache.sets
        print(
            f"  victim access {i}: addr=0x{address:x}, "
            f"maps_to=(set={result.set_index}, tag={result.tag}), "
            f"{'hit' if result.hit else 'miss'}, latency={result.latency:.1f}"
        )
        print(f"    before set {result.set_index}: {format_tag_list(before[result.set_index])}")
        print(f"    after  set {result.set_index}: {format_tag_list(after[result.set_index])}")
    print_cache_state("Cache state after victim:", cache)

    # 3. Probe
    print("\n--- Step 3: Attacker probe ---")
    timing_vector: list[float] = []
    probe_details: list[list[str]] = []
    for logical_set_index, per_set in enumerate(attacker_addresses):
        physical_set_index = monitored_labels[logical_set_index]
        total = 0.0
        details_for_set: list[str] = []
        print(f"  probe monitored set {physical_set_index}:")
        probe_sequence = per_set if args.probe_order == "forward" else list(reversed(per_set))
        for address in probe_sequence:
            before = deepcopy(cache.sets)
            result = cache.access(address)
            total += result.latency
            status = "hit" if result.hit else "miss"
            detail = f"tag {result.tag}: {status}, {result.latency:.1f}"
            details_for_set.append(detail)
            print(
                f"    addr=0x{address:x}, maps_to=(set={result.set_index}, tag={result.tag}), "
                f"{status}, latency={result.latency:.1f}"
            )
            if before[result.set_index] != cache.sets[result.set_index]:
                print(f"      before set {result.set_index}: {format_tag_list(before[result.set_index])}")
                print(f"      after  set {result.set_index}: {format_tag_list(cache.sets[result.set_index])}")
        print(f"    total probe time for set {physical_set_index}: {total:.1f}")
        timing_vector.append(total)
        probe_details.append(details_for_set)

    print("\nFinal timing vector:")
    print("  [" + ", ".join(f"{x:.1f}" for x in timing_vector) + "]")

    print("\nCompact interpretation:")
    for logical_index, total in enumerate(timing_vector):
        physical_set_index = monitored_labels[logical_index]
        print(f"  set {physical_set_index}: total={total:.1f} ({'; '.join(probe_details[logical_index])})")

    print("\nKey idea:")
    print("  If one monitored set has a larger probe time, the victim likely disturbed that set.")
    print("  The evaluator later uses many timing vectors like this to infer the secret statistically.")
    print("  Note: probe accesses still update the cache. Reverse order just avoids probe self-evicting")
    print("  the attacker line that survived the victim access in this simple 2-way example.")


if __name__ == "__main__":
    main()
