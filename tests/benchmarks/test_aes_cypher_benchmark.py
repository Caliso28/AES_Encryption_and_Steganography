"""Opt-in AES benchmarks: pytest -o addopts= -m benchmark tests/benchmarks."""

import os
import secrets
import time

import psutil
import pytest

from crypto.aes_cipher import AESCipher


KEY = b"0123456789abcdef0123456789abcdef"
NONCE = b"012345678901"


@pytest.fixture
def cipher():
    return AESCipher()


@pytest.mark.benchmark
@pytest.mark.parametrize("size", [1024, 1024 * 1024, 10 * 1024 * 1024])
def test_encryption_performance(cipher, benchmark, size):
    data = secrets.token_bytes(size)
    encrypted = benchmark(cipher.encrypt, KEY, NONCE, data)
    assert cipher.decrypt(KEY, NONCE, encrypted) == data


@pytest.mark.benchmark
@pytest.mark.parametrize("size", [1024, 1024 * 1024, 10 * 1024 * 1024])
def test_decryption_performance(cipher, benchmark, size):
    data = secrets.token_bytes(size)
    encrypted = cipher.encrypt(KEY, NONCE, data)
    decrypted = benchmark(cipher.decrypt, KEY, NONCE, encrypted)
    assert decrypted == data


@pytest.mark.benchmark
@pytest.mark.parametrize("data_size_mb", [1, 5, 10])
def test_encryption_throughput(cipher, data_size_mb):
    data = secrets.token_bytes(data_size_mb * 1024 * 1024)

    start_time = time.perf_counter()
    cipher.encrypt(KEY, NONCE, data)
    elapsed = time.perf_counter() - start_time

    throughput_mbps = data_size_mb / elapsed

    assert elapsed > 0, "Chiffrement trop rapide pour mesurer"
    print(f"\nDébit chiffrement ({data_size_mb} MB): {throughput_mbps:.2f} MB/s")
    assert throughput_mbps > 0


@pytest.mark.benchmark
@pytest.mark.parametrize("data_size_mb", [1, 5, 10])
def test_decryption_throughput(cipher, data_size_mb):
    data = secrets.token_bytes(data_size_mb * 1024 * 1024)
    encrypted = cipher.encrypt(KEY, NONCE, data)

    start_time = time.perf_counter()
    cipher.decrypt(KEY, NONCE, encrypted)
    elapsed = time.perf_counter() - start_time

    throughput_mbps = data_size_mb / elapsed

    assert elapsed > 0, "Déchiffrement trop rapide pour mesurer"
    print(f"\nDébit déchiffrement ({data_size_mb} MB): {throughput_mbps:.2f} MB/s")
    assert throughput_mbps > 0


@pytest.mark.benchmark
def test_encryption_memory_consumption():
    cipher = AESCipher()
    data_size_mb = 5
    data = secrets.token_bytes(data_size_mb * 1024 * 1024)

    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / (1024 * 1024)

    cipher.encrypt(KEY, NONCE, data)

    mem_after = process.memory_info().rss / (1024 * 1024)
    mem_delta = mem_after - mem_before

    print(f"\nMémoire avant: {mem_before:.2f} MB")
    print(f"Mémoire après: {mem_after:.2f} MB")
    print(f"Delta: {mem_delta:.2f} MB")

    assert mem_delta < data_size_mb * 3, (
        f"Consommation mémoire excessive: {mem_delta:.2f} MB "
        f"pour {data_size_mb} MB de données"
    )


@pytest.mark.benchmark
def test_decryption_memory_consumption():
    cipher = AESCipher()
    data_size_mb = 5
    data = secrets.token_bytes(data_size_mb * 1024 * 1024)
    encrypted = cipher.encrypt(KEY, NONCE, data)

    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / (1024 * 1024)

    cipher.decrypt(KEY, NONCE, encrypted)

    mem_after = process.memory_info().rss / (1024 * 1024)
    mem_delta = mem_after - mem_before

    print(f"\nMémoire avant: {mem_before:.2f} MB")
    print(f"Mémoire après: {mem_after:.2f} MB")
    print(f"Delta: {mem_delta:.2f} MB")

    assert mem_delta < data_size_mb * 3, (
        f"Consommation mémoire excessive: {mem_delta:.2f} MB "
        f"pour {data_size_mb} MB de données"
    )
