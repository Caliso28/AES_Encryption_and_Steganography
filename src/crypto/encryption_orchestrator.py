"""Password-based encryption for in-memory byte strings."""

import base64
import binascii
import secrets
from .aes_cipher import AESCipher
from .key_derivator import KeyDerivator
from .exceptions import CryptoError, IntegrityError, ValidationError


class EncryptionOrchestrator:
    """Combine password encoding, Argon2id, and AES-GCM for byte payloads.

    The returned mapping contains Base64-encoded ``salt``, ``nonce``, and
    ``ciphertext`` fields. It is a convenient in-memory format and is separate
    from the versioned streaming file format.
    """

    def __init__(self, key_derivator: KeyDerivator, aes_cipher: AESCipher):
        """Create an orchestrator using the supplied derivator and cipher.

        Args:
            key_derivator: Component used to derive an AES key from a password.
            aes_cipher: Component used for AES-GCM encryption and decryption.
        """
        self.key_derivator = key_derivator
        self.aes_cipher = aes_cipher
        self.used_nonces_by_key = {}

    def encrypt(self, password: str, data: bytes) -> dict:
        """Encrypt bytes and return their Base64-encoded components.

        A fresh random salt and nonce are generated for every call.

        Args:
            password: Password encoded as UTF-8.
            data: Plaintext bytes.

        Returns:
            A mapping with Base64 string values for ``salt``, ``nonce``, and
            ``ciphertext``.

        Raises:
            ValidationError: If the password or payload is invalid, or an
                unexpected validation/encryption failure occurs.
        """
        try:
            password_bytes = self._encode_password(password)
            if not isinstance(data, bytes):
                raise ValidationError("The data to be encrypted must be of the 'byte' type.")

            salt = secrets.token_bytes(16)
            key = self.key_derivator.derive(password_bytes, salt)
            nonce = secrets.token_bytes(12)

            used_nonces = self.used_nonces_by_key.setdefault(key, set())
            if nonce in used_nonces:
                raise ValidationError("Nonce already used by this key: security compromise.")
            used_nonces.add(nonce)

            ciphertext = self.aes_cipher.encrypt(key, nonce, data)
            return {
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
            encrypted_data: Mapping with Base64 string fields ``salt``,
                ``nonce``, and ``ciphertext``.

        Returns:
            The decrypted plaintext bytes.

        Raises:
            ValidationError: If the mapping, its fields, or Base64 values are
                invalid.
            IntegrityError: If authentication fails or the password is wrong.
        """
        try:
            password_bytes = self._encode_password(password)
            if not isinstance(encrypted_data, dict):
                raise ValidationError("The numerical data must be a dictionary.")

            required_fields = ("salt", "nonce", "ciphertext")
            if any(field not in encrypted_data for field in required_fields):
                raise ValidationError(
                    "One or more fields in the numerical data are missing."
                )

            encoded_values = tuple(encrypted_data[field] for field in required_fields)
            if not all(isinstance(value, str) for value in encoded_values):
                raise ValidationError("The fields containing numerical data must be in Base64.")

            salt, nonce, ciphertext = (
                base64.b64decode(value, validate=True) for value in encoded_values
            )
        except (binascii.Error, ValueError) as e:
            raise ValidationError(
                "The data contains invalid Base64 encoding."
            ) from e
        except CryptoError:
            raise
        except Exception as e:
            raise ValidationError("The cyphered datas or the password are invalid.") from e

        try:
            key = self.key_derivator.derive(password_bytes, salt)
        except CryptoError:
            raise
        except Exception as e:
            raise ValidationError("Key derivation failed.") from e

        try:
            return self.aes_cipher.decrypt(key, nonce, ciphertext)
        except IntegrityError:
            raise
        except ValidationError:
            raise
        except Exception as e:
            raise IntegrityError(
                "Decryption failed: incorrect password or corrupted data."
            ) from e

    @staticmethod
    def _encode_password(password: str) -> bytes:
        """Encode a string password as UTF-8 or reject invalid input.

        Args:
            password: Password string to encode.

        Returns:
            UTF-8 encoded password bytes.

        Raises:
            ValidationError: If the value is not a string or cannot be encoded.
        """
        if not isinstance(password, str):
            raise ValidationError("The password must be of type “str.”")
        try:
            return password.encode("utf-8")
        except UnicodeEncodeError as e:
            raise ValidationError("The password cannot be encoded in UTF-8.") from e
