"""Opt-in orchestrator benchmarks: pytest -o addopts= -m benchmark tests/benchmarks."""

import secrets

import pytest

from crypto.aes_cipher import AESCipher
from crypto.encryption_orchestrator import EncryptionOrchestrator
from crypto.key_derivator import KeyDerivator


PASSWORD = "mot de passe de benchmark"


@pytest.fixture
def orchestrator():
    return EncryptionOrchestrator(
        KeyDerivator(memory_cost=8 * 1024, time_cost=1, parallelism=1),
        AESCipher(),
    )


@pytest.mark.benchmark
@pytest.mark.parametrize("size", [1024, 1024 * 1024])
def test_full_encryption_performance(orchestrator, benchmark, size):
    data = secrets.token_bytes(size)

    encrypted = benchmark.pedantic(
        orchestrator.encrypt,
        args=(PASSWORD, data),
        iterations=1,
        rounds=3,
    )

    assert orchestrator.decrypt(PASSWORD, encrypted) == data


@pytest.mark.benchmark
@pytest.mark.parametrize("size", [1024, 1024 * 1024])
def test_full_decryption_performance(orchestrator, benchmark, size):
    data = secrets.token_bytes(size)
    encrypted = orchestrator.encrypt(PASSWORD, data)

    decrypted = benchmark.pedantic(
        orchestrator.decrypt,
        args=(PASSWORD, encrypted),
        iterations=1,
        rounds=3,
    )

    assert decrypted == data
