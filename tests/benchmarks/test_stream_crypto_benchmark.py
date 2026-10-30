"""Opt-in stream benchmarks: pytest -o addopts= -m benchmark tests/benchmarks."""

import io

import pytest

from config import Crypto
from crypto.stream_crypto import decrypt_stream, encrypt_stream


PASSWORD = "mot de passe de benchmark"


@pytest.fixture
def config():
    return Crypto(
        CHUNK_SIZE=64 * 1024,
        MEMORY_COST=8 * 1024,
        TIME_COST=1,
        PARALLELISM=1,
    )


@pytest.mark.benchmark
@pytest.mark.parametrize("size", [0, 64 * 1024, 1024 * 1024])
def test_encrypt_stream_benchmark(benchmark, config, size):
    data = b"x" * size

    encrypted = benchmark.pedantic(
        lambda: b"".join(encrypt_stream(io.BytesIO(data), PASSWORD, config)),
        iterations=1,
        rounds=3,
    )

    assert b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config)) == data


@pytest.mark.benchmark
@pytest.mark.parametrize("size", [0, 64 * 1024, 1024 * 1024])
def test_decrypt_stream_benchmark(benchmark, config, size):
    data = b"x" * size
    encrypted = b"".join(encrypt_stream(io.BytesIO(data), PASSWORD, config))

    decrypted = benchmark.pedantic(
        lambda: b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config)),
        iterations=1,
        rounds=3,
    )

    assert decrypted == data
