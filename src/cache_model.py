"""A small set-associative cache model for trace-driven leakage testing.

This is intentionally simplified. It models only the ideas we need for the
project prototype: set index, tag, ways, LRU replacement, hit/miss latency,
and optional Gaussian timing noise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple
import random


@dataclass
class CacheConfig:
    num_sets: int = 8
    ways: int = 2
    line_size: int = 64
    hit_latency: float = 10.0
    miss_latency: float = 30.0
    noise_std: float = 1.0


@dataclass
class CacheAccessResult:
    address: int
    set_index: int
    tag: int
    hit: bool
    latency: float


@dataclass
class SetAssociativeCache:
    config: CacheConfig
    rng: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        # Each cache set stores tags ordered from least-recently-used to most-recently-used.
        self.sets: List[List[int]] = [[] for _ in range(self.config.num_sets)]

    def address_to_set_tag(self, address: int) -> Tuple[int, int]:
        """Map a byte address to a simplified cache set index and tag."""
        if address < 0:
            raise ValueError("Address must be non-negative")
        block_addr = address // self.config.line_size
        set_index = block_addr % self.config.num_sets
        tag = block_addr // self.config.num_sets
        return set_index, tag

    def _sample_latency(self, hit: bool) -> float:
        base = self.config.hit_latency if hit else self.config.miss_latency
        if self.config.noise_std <= 0:
            return base
        return max(0.0, base + self.rng.gauss(0.0, self.config.noise_std))

    def access(self, address: int) -> CacheAccessResult:
        """Access one address, update cache state, and return hit/miss timing."""
        set_index, tag = self.address_to_set_tag(address)
        cache_set = self.sets[set_index]

        if tag in cache_set:
            # Hit: move this tag to the MRU position.
            cache_set.remove(tag)
            cache_set.append(tag)
            hit = True
        else:
            # Miss: insert this tag; evict LRU if the set is full.
            if len(cache_set) >= self.config.ways:
                cache_set.pop(0)
            cache_set.append(tag)
            hit = False

        latency = self._sample_latency(hit)
        return CacheAccessResult(address, set_index, tag, hit, latency)


def address_for_set(set_index: int, tag: int, config: CacheConfig) -> int:
    """Construct an address that maps to a given set and tag."""
    if not 0 <= set_index < config.num_sets:
        raise ValueError("set_index out of range")
    if tag < 0:
        raise ValueError("tag must be non-negative")
    block_addr = tag * config.num_sets + set_index
    return block_addr * config.line_size
