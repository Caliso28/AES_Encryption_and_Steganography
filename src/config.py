"""Project-wide settings grouped by feature."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final


TAG_SIZE: Final[int] = 16
SALT_SIZE: Final[int] = 16
NONCE_BASE_SIZE: Final[int] = 4
MAX_KDF_MEMORY_COST: Final[int] = 256 * 1024
MAX_KDF_TIME_COST: Final[int] = 5
MAX_KDF_PARALLELISM: Final[int] = 16
MAX_CONCURRENT_KDFS: Final[int] = 1
KDF_QUEUE_TIMEOUT_SECONDS: Final[float] = 1.0
ABSOLUTE_MAX_CHUNK_SIZE: Final[int] = 1024 * 1024


class KDFProfile(str, Enum):
    """Security policy applied to Argon2id parameters."""

    PRODUCTION = "production"
    TEST = "test"
    DECRYPTION = "decryption"


@dataclass(frozen=True)
class Crypto:
    """Magic identifier, chunking, and Argon2id parameters for crypto operations.

    Structural format sizes are fixed by the module-level constants. The
    defaults define production Argon2id costs and maximum accepted resource
    costs during decryption. Use the test profile explicitly when creating
    streams with low costs for automated tests.

    Attributes:
        MAGIC_BYTES: Four-byte format/version identifier stored in each header.
        CHUNK_SIZE: Plaintext bytes processed per encrypted stream record.
        TIME_COST: Default Argon2id iteration count.
        MEMORY_COST: Default Argon2id memory cost in KiB.
        PARALLELISM: Default Argon2id lane count.
        KDF_PROFILE: Security policy applied to parameters used for encryption.
        MAX_TIME_COST: Maximum KDF iterations accepted from a file header.
        MAX_MEMORY_COST: Maximum KDF memory accepted from a file header, in KiB.
        MAX_PARALLELISM: Maximum KDF lanes accepted from a file header.
        MAX_CHUNK_SIZE: Maximum plaintext chunk size accepted from a header,
            which may be lowered but not raised above
            ``ABSOLUTE_MAX_CHUNK_SIZE``.
    """

    MAGIC_BYTES: bytes = b"CRP1"
    CHUNK_SIZE: int = 65536

    # Memory-hard defaults raise the cost of offline password guessing while
    # remaining practical for interactive use.
    TIME_COST: int = 3
    MEMORY_COST: int = 65536
    PARALLELISM: int = 4
    KDF_PROFILE: KDFProfile = KDFProfile.PRODUCTION

    # Header values are untrusted, so cap KDF work before deriving a key to
    # prevent crafted files from exhausting local resources.
    MAX_TIME_COST: int = MAX_KDF_TIME_COST
    MAX_MEMORY_COST: int = MAX_KDF_MEMORY_COST
    MAX_PARALLELISM: int = MAX_KDF_PARALLELISM
    MAX_CHUNK_SIZE: int = ABSOLUTE_MAX_CHUNK_SIZE


@dataclass(frozen=True)
class Steganography:
    """Settings for steganography features."""


@dataclass
class Files:
    """Mutable default paths and other settings for file operations."""

    dest_path: str | Path | None = None


files: Files = Files()
"""Project-wide file-operation settings used when a function destination is omitted."""
