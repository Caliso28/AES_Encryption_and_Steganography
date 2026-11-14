"""Password-based encryption for in-memory byte strings."""

import base64
import binascii
import json
import secrets
from config import (
    KDFProfile,
    MAX_KDF_MEMORY_COST,
    MAX_KDF_PARALLELISM,
    MAX_KDF_TIME_COST,
)
from .aes_cipher import AESCipher
from .key_derivator import KeyDerivator
from .exceptions import (
    CryptoError,
    IntegrityError,
    UnsupportedVersionError,
    ValidationError,
)
from .password_utils import prepare_password


_FORMAT_VERSION = 1
_ALGORITHM = "AES-GCM"
_KDF_ALGORITHM = "Argon2id"
_PASSWORD_ENCODING = "UTF-8"
_PASSWORD_NORMALIZATION = "NFC"
_DATA_FIELDS = ("salt", "nonce", "ciphertext")
_VERSIONED_FIELDS = (
    "version",
    "algorithm",
    "kdf",
    "password_encoding",
    "password_normalization",
    *_DATA_FIELDS,
)


class EncryptionOrchestrator:
    """Combine password encoding, Argon2id, and AES-GCM for byte payloads.

    The returned mapping contains versioned algorithm and Argon2id metadata,
    plus Base64-encoded ``salt``, ``nonce``, and ``ciphertext`` fields.
    Passwords are normalized to NFC before UTF-8 encoding.
    """

    def __init__(self, key_derivator: KeyDerivator, aes_cipher: AESCipher):
        """Create an orchestrator using the supplied derivator and cipher.

        Args:
            key_derivator: Component used to derive an AES key from a password.
            aes_cipher: Component used for AES-GCM encryption and decryption.
        """
        self.key_derivator = key_derivator
        self.aes_cipher = aes_cipher

    def encrypt(self, password: str, data: bytes) -> dict:
        """Encrypt bytes and return a versioned mapping of encoded components.

        A fresh random salt and nonce are generated for every call.
        Passwords are normalized to Unicode NFC before UTF-8 encoding.

        Args:
            password: Password normalized to NFC and encoded as UTF-8.
            data: Plaintext bytes.

        Returns:
            A versioned mapping containing algorithm/KDF metadata and Base64
            string values for ``salt``, ``nonce``, and ``ciphertext``.

        Raises:
            ValidationError: If the password or payload is invalid, or an
                unexpected validation/encryption failure occurs.
        """
        try:
            password_bytes = prepare_password(password)
            if not password_bytes:
                raise ValidationError("The password must not be empty.")
            if not isinstance(data, bytes):
                raise ValidationError("The data to be encrypted must be of the 'byte' type.")

            metadata = self._metadata()
            salt = secrets.token_bytes(16)
            key = self.key_derivator.derive(password_bytes, salt)
            nonce = secrets.token_bytes(12)

            ciphertext = self.aes_cipher.encrypt(
                key, nonce, data, associated_data=self._associated_data(metadata)
            )
            return {
                **metadata,
                "salt": base64.b64encode(salt).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            }
        except CryptoError:
            raise
        except Exception as e:
            raise ValidationError("Failure to validate or encrypt the data.") from e

    def decrypt(self, password: str, encrypted_data: dict) -> bytes:
        """Decode, authenticate, and decrypt an encrypted payload.

        Args:
            password: Password used to encrypt the payload.
            encrypted_data: Versioned mapping with algorithm/KDF metadata and
                Base64 string fields.

        Returns:
            The decrypted plaintext bytes.

        Raises:
            ValidationError: If the mapping, its fields, or Base64 values are
                invalid.
            UnsupportedVersionError: If the mapping uses an unknown version.
            IntegrityError: If authentication fails or the password is wrong.
        """
        try:
            if not isinstance(encrypted_data, dict):
                raise ValidationError("The numerical data must be a dictionary.")

            if any(field not in encrypted_data for field in _VERSIONED_FIELDS):
                raise ValidationError(
                    "One or more fields in the numerical data are missing."
                )
            metadata = self._validate_metadata(encrypted_data)

            encoded_values = tuple(encrypted_data[field] for field in _DATA_FIELDS)
            if not all(isinstance(value, str) for value in encoded_values):
                raise ValidationError("The fields containing numerical data must be in Base64.")

            salt, nonce, ciphertext = (
                base64.b64decode(value, validate=True) for value in encoded_values
            )
            if len(salt) != 16:
                raise ValidationError("Invalid salt length.")
            if len(nonce) != 12:
                raise ValidationError("Invalid nonce length.")
            if len(ciphertext) < 16:
                raise ValidationError("Ciphertext is too short.")
            password_bytes = prepare_password(password)
            if not password_bytes:
                raise ValidationError("The password must not be empty.")
        except (binascii.Error, ValueError) as e:
            raise ValidationError(
                "The data contains invalid Base64 encoding."
            ) from e
        except UnsupportedVersionError:
            raise
        except CryptoError:
            raise
        except Exception as e:
            raise ValidationError("The cyphered datas or the password are invalid.") from e

        try:
            key_derivator = self._derivator_for(metadata["kdf"])
            associated_data = self._associated_data(metadata)
            key = key_derivator.derive(password_bytes, salt)
        except CryptoError:
            raise
        except Exception as e:
            raise ValidationError("Key derivation failed.") from e

        try:
            return self.aes_cipher.decrypt(
                key, nonce, ciphertext, associated_data=associated_data
            )
        except IntegrityError:
            raise
        except ValidationError:
            raise
        except Exception as e:
            raise IntegrityError(
                "Decryption failed: incorrect password or corrupted data."
            ) from e

    def _metadata(self) -> dict:
        """Return the immutable algorithm and KDF parameters for this record."""
        return {
            "version": _FORMAT_VERSION,
            "algorithm": _ALGORITHM,
            "kdf": {
                "algorithm": _KDF_ALGORITHM,
                "length": self.key_derivator.length,
                "memory_cost": self.key_derivator.memory_cost,
                "time_cost": self.key_derivator.time_cost,
                "parallelism": self.key_derivator.parallelism,
            },
            "password_encoding": _PASSWORD_ENCODING,
            "password_normalization": _PASSWORD_NORMALIZATION,
        }

    @staticmethod
    def _associated_data(metadata: dict) -> bytes:
        """Serialize metadata canonically so AES-GCM authenticates its meaning."""
        return json.dumps(
            metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def _validate_metadata(self, encrypted_data: dict) -> dict:
        """Validate the versioned format metadata before deriving a key."""
        version = encrypted_data["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValidationError("The encrypted data version must be an integer.")
        if version != _FORMAT_VERSION:
            raise UnsupportedVersionError(
                f"Unsupported in-memory encryption format version: {version}."
            )
        if any(field not in encrypted_data for field in _VERSIONED_FIELDS):
            raise ValidationError(
                "One or more fields in the numerical data are missing."
            )
        if encrypted_data["algorithm"] != _ALGORITHM:
            raise ValidationError("The encryption algorithm is unsupported.")
        if encrypted_data["password_encoding"] != _PASSWORD_ENCODING:
            raise ValidationError("The password encoding is unsupported.")
        if encrypted_data["password_normalization"] != _PASSWORD_NORMALIZATION:
            raise ValidationError("The password normalization is unsupported.")

        kdf = encrypted_data["kdf"]
        if not isinstance(kdf, dict) or set(kdf) != {
            "algorithm",
            "length",
            "memory_cost",
            "time_cost",
            "parallelism",
        }:
            raise ValidationError("The Argon2id parameters are invalid.")
        if kdf["algorithm"] != _KDF_ALGORITHM:
            raise ValidationError("The key derivation algorithm is unsupported.")
        for field in ("length", "memory_cost", "time_cost", "parallelism"):
            value = kdf[field]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValidationError(f"The Argon2id {field} must be a positive integer.")
        if kdf["length"] not in (16, 24, 32):
            raise ValidationError("The Argon2id key length is unsupported by AES-GCM.")
        if (
            kdf["memory_cost"] > MAX_KDF_MEMORY_COST
            or kdf["time_cost"] > MAX_KDF_TIME_COST
            or kdf["parallelism"] > MAX_KDF_PARALLELISM
            or kdf["memory_cost"] < 8 * kdf["parallelism"]
        ):
            raise ValidationError("The Argon2id parameters exceed permitted limits.")
        if self.key_derivator.profile is not KDFProfile.TEST and (
            kdf["memory_cost"] < 64 * 1024
            or kdf["time_cost"] < 3
            or kdf["parallelism"] < 4
        ):
            raise ValidationError(
                "The Argon2id parameters are below the production minimums."
            )
        return {
            key: encrypted_data[key]
            for key in (
                "version",
                "algorithm",
                "kdf",
                "password_encoding",
                "password_normalization",
            )
        }

    def _derivator_for(self, parameters: dict) -> KeyDerivator:
        """Use recorded KDF parameters, bounded by the local decryption policy."""
        if (
            self.key_derivator.profile is KDFProfile.TEST
            and parameters["length"] == self.key_derivator.length
            and parameters["memory_cost"] == self.key_derivator.memory_cost
            and parameters["time_cost"] == self.key_derivator.time_cost
            and parameters["parallelism"] == self.key_derivator.parallelism
        ):
            return self.key_derivator
        return KeyDerivator(
            length=parameters["length"],
            memory_cost=parameters["memory_cost"],
            time_cost=parameters["time_cost"],
            parallelism=parameters["parallelism"],
            profile=(
                KDFProfile.TEST
                if self.key_derivator.profile is KDFProfile.TEST
                else KDFProfile.DECRYPTION
            ),
            max_memory_cost=MAX_KDF_MEMORY_COST,
            max_time_cost=MAX_KDF_TIME_COST,
            max_parallelism=MAX_KDF_PARALLELISM,
        )
