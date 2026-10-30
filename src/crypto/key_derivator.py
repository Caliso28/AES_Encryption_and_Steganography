"""Argon2id key derivation for password-based encryption."""

from typing import Union
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

class KeyDerivator:
    """Derive fixed-length keys from a password and salt using Argon2id."""

    def __init__(
            self,
            length : int = 32,
            memory_cost : int = 65536,
            time_cost : int = 3,
            parallelism : int = 4
    ) :
        """Configure the output length and Argon2id work factors.

        Args:
            length: Derived key length in bytes.
            memory_cost: Argon2id memory cost in KiB.
            time_cost: Number of Argon2id iterations.
            parallelism: Number of Argon2id lanes.
        """
        self.length = length
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism

    def derive(self, password: Union[str, bytes], salt: bytes) -> bytes:
        """Derive a key from a UTF-8 string or bytes password.

        Args:
            password: Password material supplied as text or raw bytes.
            salt: Salt passed to Argon2id; callers should use a fresh,
                unpredictable salt for each independent encryption.

        Returns:
            A byte string of ``length`` bytes.

        Raises:
            TypeError: If the supplied password or salt is not accepted by the
                underlying Argon2id implementation.
            ValueError: If Argon2id rejects the configured parameters.
        """
        password_bytes = password.encode("utf-8") if isinstance(password, str) else password
        # Passwords have less entropy than random keys, so a memory-hard KDF
        # makes offline guessing more expensive; the salt prevents key reuse.
        kdf = Argon2id(
            salt = salt,
            length = self.length,
            iterations = self.time_cost,
            lanes = self.parallelism,
            memory_cost = self.memory_cost
        )
        return kdf.derive(password_bytes)
