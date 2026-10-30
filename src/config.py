"""Project-wide settings grouped by feature."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Crypto:
    """Format, chunking, and Argon2id parameters for cryptographic operations.

    The defaults define the current stream format and the maximum accepted
    resource costs during decryption. Creating a custom instance is useful for
    tests and for choosing different encryption costs; decryption still enforces
    the configured upper bounds.

    Attributes:
        MAGIC_BYTES: Four-byte format/version identifier stored in each header.
        TAG_SIZE: Authentication-tag size in bytes.
        SALT_SIZE: Argon2id salt size in bytes.
        NONCE_BASE_SIZE: Random prefix size combined with a per-chunk counter.
        CHUNK_SIZE: Plaintext bytes processed per encrypted stream record.
        TIME_COST: Default Argon2id iteration count.
        MEMORY_COST: Default Argon2id memory cost in KiB.
        PARALLELISM: Default Argon2id lane count.
        MAX_TIME_COST: Maximum KDF iterations accepted from a file header.
        MAX_MEMORY_COST: Maximum KDF memory accepted from a file header, in KiB.
        MAX_PARALLELISM: Maximum KDF lanes accepted from a file header.
        MAX_CHUNK_SIZE: Maximum plaintext chunk size accepted from a header.
    """

    MAGIC_BYTES: bytes = b"CRP1"
    TAG_SIZE: int = 16
    SALT_SIZE: int = 16
    NONCE_BASE_SIZE: int = 4
    CHUNK_SIZE: int = 65536

    # Memory-hard defaults raise the cost of offline password guessing while
    # remaining practical for interactive use.
    TIME_COST: int = 3
    MEMORY_COST: int = 65536
    PARALLELISM: int = 4

    # Header values are untrusted, so cap KDF work before deriving a key to
    # prevent crafted files from exhausting local resources.
    MAX_TIME_COST: int = 10
    MAX_MEMORY_COST: int = 1024 * 1024  #1 GiB max
    MAX_PARALLELISM: int = 16
    MAX_CHUNK_SIZE: int = 1024 * 1024


@dataclass(frozen=True)
class Steganography:
    """Settings for steganography features."""


@dataclass
class Files:
    """Mutable default paths and other settings for file operations."""

    dest_path: str | Path | None = None


files: Files = Files()
"""Project-wide file-operation settings used when a function destination is omitted."""
