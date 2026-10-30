"""Low-level AES-GCM authenticated encryption."""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .exceptions import ValidationError, IntegrityError

class AESCipher:
    """Encrypt and authenticate bytes with AES-GCM.

    A new instance can be reused; key and nonce management are the caller's
    responsibility. Nonces must be unique for each encryption under a key.
    """

    def encrypt(self, key: bytes, nonce: bytes, data: bytes, associated_data: bytes|None=None) -> bytes:
        """Encrypt bytes and append the GCM authentication tag.

        Args:
            key: AES key of 16, 24, or 32 bytes.
            nonce: 12-byte GCM nonce, unique for this key.
            data: Plaintext bytes.
            associated_data: Optional bytes authenticated but not encrypted.

        Returns:
            Ciphertext followed by the 16-byte authentication tag.

        Raises:
            ValidationError: If the key or nonce has an invalid length.
        """
        # GCM's 96-bit nonce is its standard efficient size and keeps nonce
        # construction consistent across the in-memory and stream APIs.
        if len(nonce) != 12:
            raise ValidationError("Nonce length is not optimal.")
        if len(key) not in (16, 24, 32):
            raise ValidationError("Invalid AES key size.")
        
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, data, associated_data=associated_data)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes|None=None) -> bytes:
        """Authenticate and decrypt an AES-GCM ciphertext.

        Args:
            key: AES key of 16, 24, or 32 bytes.
            nonce: The 12-byte nonce used for encryption.
            ciphertext: Ciphertext including its authentication tag.
            associated_data: The same optional bytes supplied during encryption.

        Returns:
            The authenticated plaintext.

        Raises:
            ValidationError: If the key or nonce has an invalid length.
            IntegrityError: If authentication fails, including for a wrong key,
                nonce, associated-data value, or modified ciphertext.
        """
        if len(nonce) != 12:
            raise ValidationError("Nonce length is not optimal.")
        if len(key) not in (16, 24, 32):
            raise ValidationError("Invalid AES key size")
        
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, associated_data=associated_data)
        except InvalidTag:
            raise IntegrityError("Decryption failed: key, nonce, or data corrupted.")
