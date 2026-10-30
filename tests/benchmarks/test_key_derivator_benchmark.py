"""Opt-in key derivation benchmarks: pytest -o addopts= -m benchmark tests/benchmarks."""

import pytest

from crypto.key_derivator import KeyDerivator


PASSWORD = "mot de passe de benchmark"
SALT = b"salt de benchmark"


@pytest.mark.benchmark
@pytest.mark.parametrize("memory_cost", [8 * 1024, 16 * 1024])
def test_memory_cost_benchmark(benchmark, memory_cost):
    derivator = KeyDerivator(memory_cost=memory_cost, time_cost=1, parallelism=1)

    benchmark.pedantic(
        derivator.derive,
        args=(PASSWORD, SALT),
        iterations=1,
        rounds=3,
    )
    assert len(derivator.derive(PASSWORD, SALT)) == derivator.length


@pytest.mark.benchmark
@pytest.mark.parametrize("time_cost", [1, 2])
def test_time_cost_benchmark(benchmark, time_cost):
    derivator = KeyDerivator(memory_cost=8 * 1024, time_cost=time_cost, parallelism=1)

    benchmark.pedantic(
        derivator.derive,
        args=(PASSWORD, SALT),
        iterations=1,
        rounds=3,
    )
    assert len(derivator.derive(PASSWORD, SALT)) == derivator.length


@pytest.mark.benchmark
@pytest.mark.parametrize("parallelism", [1, 2])
def test_parallelism_benchmark(benchmark, parallelism):
    derivator = KeyDerivator(
        memory_cost=16 * 1024,
        time_cost=1,
        parallelism=parallelism,
    )

    benchmark.pedantic(
        derivator.derive,
        args=(PASSWORD, SALT),
        iterations=1,
        rounds=3,
    )
    assert len(derivator.derive(PASSWORD, SALT)) == derivator.length


@pytest.mark.benchmark
def test_default_parameters_benchmark(benchmark):
    derivator = KeyDerivator()

    benchmark.pedantic(
        derivator.derive,
        args=(PASSWORD, SALT),
        iterations=1,
        rounds=3,
    )
    assert len(derivator.derive(PASSWORD, SALT)) == derivator.length


@pytest.mark.benchmark
def test_repeated_derivations_benchmark(benchmark):
    derivator = KeyDerivator(memory_cost=8 * 1024, time_cost=1, parallelism=1)

    def derive_three_times():
        return [derivator.derive(PASSWORD, SALT) for _ in range(3)]

    keys = benchmark.pedantic(derive_three_times, iterations=1, rounds=3)

    assert len(keys) == 3
    assert all(len(key) == derivator.length for key in keys)
