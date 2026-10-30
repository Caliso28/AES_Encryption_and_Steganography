"""Opt-in benchmarks: pytest -o addopts= -m benchmark tests/benchmarks."""

import pytest

from config import Crypto
from crypto.file_cipher import encrypt_file


PASSWORD = "mot de passe de benchmark"


@pytest.mark.benchmark
@pytest.mark.parametrize(
    "file_size",
    [0, 64 * 1024, 1024 * 1024],
    ids=["empty", "64-kib", "1-mib"],
)
def test_encrypt_file_benchmark(benchmark, tmp_path, file_size):
    source = tmp_path / "payload.bin"
    source.write_bytes(b"x" * file_size)
    config = Crypto()

    def encrypt():
        return encrypt_file(source, PASSWORD, tmp_path, config)

    benchmark.pedantic(encrypt, rounds=3, iterations=1)

    outputs = list(tmp_path.glob("payload*_encrypted.bin"))
    assert len(outputs) == 3
    assert all(output.is_file() for output in outputs)
