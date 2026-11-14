"""Argon2id key derivation for password-based encryption."""

from threading import BoundedSemaphore
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from config import (
    KDFProfile,
    KDF_QUEUE_TIMEOUT_SECONDS,
    MAX_CONCURRENT_KDFS,
    MAX_KDF_MEMORY_COST,
    MAX_KDF_PARALLELISM,
    MAX_KDF_TIME_COST,
)
from .exceptions import KDFBusyError


_KDF_SEMAPHORE = BoundedSemaphore(MAX_CONCURRENT_KDFS)

class KeyDerivator:
    """Derive fixed-length keys from a password and salt using Argon2id."""

    def __init__(
            self,
            length : int = 32,
            memory_cost : int = 65536,
            time_cost : int = 3,
            parallelism : int = 4,
            profile: KDFProfile = KDFProfile.PRODUCTION,
            max_memory_cost: int | None = None,
            max_time_cost: int | None = None,
            max_parallelism: int | None = None,
    ) :
        """Configure the output length and Argon2id work factors.

        Args:
            length: Derived key length in bytes.
            memory_cost: Argon2id memory cost in KiB.
            time_cost: Number of Argon2id iterations.
            parallelism: Number of Argon2id lanes.
            profile: Security policy for the supplied costs. Production
                and normal decryption enforce secure minimums; tests may opt
                into weaker costs. Decryption also requires explicit resource
                ceilings.
            max_memory_cost: Optional maximum memory cost in KiB.
            max_time_cost: Optional maximum iteration count.
            max_parallelism: Optional maximum number of lanes.

        Raises:
            TypeError: If a numeric parameter is not an integer.
            ValueError: If a parameter is outside its profile's permitted range.
        """
        try:
            profile = KDFProfile(profile)
        except (TypeError, ValueError) as error:
            raise ValueError(f"Unknown Argon2id security profile: {profile!r}.") from error

        for name, value in (
            ("length", length),
            ("memory_cost", memory_cost),
            ("time_cost", time_cost),
            ("parallelism", parallelism),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer.")
            if value <= 0:
                raise ValueError(f"{name} must be positive.")

        if length < 4:
            raise ValueError("length must be at least 4 bytes.")
        if memory_cost < 8 * parallelism:
            raise ValueError("memory_cost must be at least 8 KiB per lane.")

        if profile is KDFProfile.PRODUCTION and (
            memory_cost < 64 * 1024 or time_cost < 3 or parallelism < 4
        ):
            raise ValueError(
                "Production Argon2id parameters must use at least "
                "64 MiB, 3 iterations, and 4 lanes."
            )
        if profile is KDFProfile.DECRYPTION and (
            memory_cost < 64 * 1024 or time_cost < 3 or parallelism < 4
        ):
            raise ValueError(
                "Decryption Argon2id parameters must use at least "
                "64 MiB, 3 iterations, and 4 lanes."
            )

        if profile is KDFProfile.PRODUCTION:
            production_limits = {
                "max_memory_cost": (max_memory_cost, MAX_KDF_MEMORY_COST),
                "max_time_cost": (max_time_cost, MAX_KDF_TIME_COST),
                "max_parallelism": (max_parallelism, MAX_KDF_PARALLELISM),
            }
            for name, (limit, production_limit) in production_limits.items():
                if limit is not None and (
                    isinstance(limit, bool) or not isinstance(limit, int)
                ):
                    raise TypeError(f"{name} must be an integer.")
                if limit is not None and limit > production_limit:
                    raise ValueError(
                        f"{name} cannot exceed the production ceiling "
                        f"of {production_limit}."
                    )

            max_memory_cost = MAX_KDF_MEMORY_COST if max_memory_cost is None else max_memory_cost
            max_time_cost = MAX_KDF_TIME_COST if max_time_cost is None else max_time_cost
            max_parallelism = MAX_KDF_PARALLELISM if max_parallelism is None else max_parallelism

        limits = {
            "max_memory_cost": (max_memory_cost, memory_cost),
            "max_time_cost": (max_time_cost, time_cost),
            "max_parallelism": (max_parallelism, parallelism),
        }
        for name, (limit, value) in limits.items():
            if limit is not None:
                if isinstance(limit, bool) or not isinstance(limit, int):
                    raise TypeError(f"{name} must be an integer.")
                if limit <= 0:
                    raise ValueError(f"{name} must be positive.")
                if value > limit:
                    raise ValueError(f"{name.removeprefix('max_')} exceeds {name}.")

        if profile is KDFProfile.DECRYPTION and any(
            limit is None for limit, _ in limits.values()
        ):
            raise ValueError("The decryption profile requires all three resource limits.")

        self.length = length
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.profile = profile

    def derive(self, password: bytes, salt: bytes) -> bytes:
        """Derive a key from prepared password bytes.

        Args:
            password: UTF-8 password bytes prepared by the calling API, or
                raw bytes when using the legacy byte-password interface.
            salt: Salt passed to Argon2id; callers should use a fresh,
                unpredictable salt for each independent encryption.

        Returns:
            A byte string of ``length`` bytes.

        Raises:
            TypeError: If ``password`` or ``salt`` is not bytes, or is not
                accepted by the underlying Argon2id implementation.
            ValueError: If Argon2id rejects the configured parameters.
        """
        if not isinstance(password, bytes):
            raise TypeError("password must be bytes already prepared by the caller.")
        # Passwords have less entropy than random keys, so a memory-hard KDF
        # makes offline guessing more expensive; the salt prevents key reuse.
        kdf = Argon2id(
            salt = salt,
            length = self.length,
            iterations = self.time_cost,
            lanes = self.parallelism,
            memory_cost = self.memory_cost
        )
        if not _KDF_SEMAPHORE.acquire(timeout=KDF_QUEUE_TIMEOUT_SECONDS):
            raise KDFBusyError(
                "Key derivation is busy; resource admission timed out."
            )
        try:
            return kdf.derive(password)
        finally:
            _KDF_SEMAPHORE.release()
