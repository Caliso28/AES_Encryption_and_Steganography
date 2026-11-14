"""Authenticated, chunked encryption and decryption for binary streams."""

import struct
import secrets
from typing import BinaryIO, Iterator, Union
from config import (
    ABSOLUTE_MAX_CHUNK_SIZE,
    Crypto,
    KDFProfile,
    NONCE_BASE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
)
from .aes_cipher import AESCipher
from .key_derivator import KeyDerivator
from .exceptions import (
    ValidationError,
    HeaderError,
    UnsupportedVersionError,
    IntegrityError,
    TruncatedStreamError,
    CryptoFileError,
    CryptoError
)
from .password_utils import prepare_password
from config import MAX_KDF_MEMORY_COST, MAX_KDF_PARALLELISM, MAX_KDF_TIME_COST

_HEADER_STRUCT = struct.Struct(f">4s{SALT_SIZE}sIIII{NONCE_BASE_SIZE}s")
_NONCE_STRUCT = struct.Struct(f">{NONCE_BASE_SIZE}sQ")
_RECORD_METADATA_STRUCT = struct.Struct(">QBI")
_FORMAT_MAGIC = b"CRP1"


def _record_aad(
    header: bytes,
    counter: int,
    end_flag: int,
    plaintext_length: int,
) -> bytes:
    """Encode the canonical CRP1 record AAD."""
    metadata = _RECORD_METADATA_STRUCT.pack(counter, end_flag, plaintext_length)
    return b"CRP1-RECORD\x00" + header + metadata


def _password_bytes(password: str | bytes) -> bytes:
    """Prepare a text password as NFC UTF-8, leaving raw bytes unchanged."""
    if isinstance(password, bytes):
        return password
    return prepare_password(password)


def _read_up_to(stream: BinaryIO, size: int) -> bytes:
    """Read up to ``size`` bytes while tolerating short stream reads.

    Args:
        stream: Binary stream with a ``read`` method.
        size: Maximum number of bytes to read.

    Returns:
        The bytes read, which may be shorter than requested at end-of-stream.

    Raises:
        ValidationError: If the stream returns a non-byte value or more bytes
            than requested.
    """
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise ValidationError("The stream must return bytes.")
        if not chunk:
            break
        if len(chunk) > size - len(data):
            raise ValidationError("The stream returned more bytes than requested.")
        data.extend(chunk)
    return bytes(data)


def encrypt_stream(
    src_stream: BinaryIO,
    password: Union[str, bytes],
    config: Crypto = Crypto()
) -> Iterator[bytes]:
    """Yield a header and authenticated ciphertext records for a binary stream.

    The function reads one chunk ahead to mark the final record. Each AES-GCM
    record authenticates the complete format header, sequence number, end
    marker, and plaintext length.
    The stream's ownership remains with the caller.

    Args:
        src_stream: Readable binary source stream.
        password: A string normalized to NFC and encoded as UTF-8, or raw
            password bytes.
        config: Chunk size and Argon2id encryption settings.

    Yields:
        The binary format header first, followed by ciphertext records (each
        including its authentication tag).

    Raises:
        ValidationError: If the stream, password, or chunk configuration is
            invalid.
        CryptoFileError: If reading the source fails.
        CryptoError: If key derivation or encryption reports a package error.
    """
    if not hasattr(src_stream, "read") or not callable(src_stream.read):
        raise ValidationError("The source stream must have a 'read' method.")
    
    if not isinstance(password, (str, bytes)):
        raise ValidationError("The password must be of type 'str' or 'bytes'.")
    if config.MAGIC_BYTES != _FORMAT_MAGIC:
        raise UnsupportedVersionError("Unsupported version or magic ID.")
    pwd_bytes = _password_bytes(password)
    if not pwd_bytes:
        raise ValidationError("The password must not be empty.")

    if (
        config.MAX_CHUNK_SIZE <= 0
        or config.MAX_CHUNK_SIZE > ABSOLUTE_MAX_CHUNK_SIZE
        or config.CHUNK_SIZE < TAG_SIZE
        or config.CHUNK_SIZE > config.MAX_CHUNK_SIZE
    ):
        raise ValidationError("Invalid chunk size in the configuration.")
    try:
        salt = secrets.token_bytes(SALT_SIZE)
        nonce_base = secrets.token_bytes(NONCE_BASE_SIZE)

        derivator = KeyDerivator(
            length=32,
            memory_cost=config.MEMORY_COST,
            time_cost=config.TIME_COST,
            parallelism=config.PARALLELISM,
            profile=config.KDF_PROFILE,
        )
        key = derivator.derive(pwd_bytes, salt)

        header = _HEADER_STRUCT.pack(
            config.MAGIC_BYTES,
            salt,
            config.TIME_COST,
            config.MEMORY_COST,
            config.PARALLELISM,
            config.CHUNK_SIZE,
            nonce_base
        )
        yield header

        cipher = AESCipher()
        counter = 0
        chunk = _read_up_to(src_stream, config.CHUNK_SIZE)
        is_last_block = False

        while not is_last_block:
            next_chunk = _read_up_to(src_stream, config.CHUNK_SIZE)
            if not next_chunk:
                is_last_block = True
                end_flag = 0x01
            else:
                end_flag = 0x00

            # A random per-stream prefix plus a counter guarantees distinct
            # nonces within the stream without generating randomness per chunk.
            nonce = _NONCE_STRUCT.pack(nonce_base, counter)
            aad = _record_aad(
                header,
                counter,
                end_flag,
                len(chunk),
            )

            encrypted_chunk = cipher.encrypt(key, nonce, chunk, associated_data=aad)
            yield encrypted_chunk

            chunk = next_chunk
            counter += 1

    except (OSError, IOError) as e:
        raise CryptoFileError("I/O error while reading the source stream.") from e
    except Exception as e:
        if isinstance(e, CryptoError):
            raise
        raise ValidationError(f"Unexpected error during encryption: {e}") from e


def decrypt_stream(
    src_stream: BinaryIO,
    password: Union[str, bytes],
    default_config: Crypto = Crypto()
) -> Iterator[bytes]:
    """Authenticate and yield plaintext records from an encrypted stream.

    Header resource limits are checked before key derivation. Each record is
    authenticated before its plaintext is yielded; callers should treat the
    complete operation as successful only after exhausting the iterator, since
    truncation can only be detected at the end.

    Args:
        src_stream: Readable binary stream in this package's encrypted format.
        password: A string normalized to NFC and encoded as UTF-8, or raw
            password bytes.
        default_config: Format identifier and upper resource limits accepted
            from the stream header.

    Yields:
        Authenticated plaintext chunks in their original order.

    Raises:
        ValidationError: If the stream, password, or configuration is invalid.
        HeaderError: If the header is malformed or uses disallowed parameters.
        UnsupportedVersionError: If the stream's magic/version is unsupported.
        IntegrityError: If a record fails authentication.
        TruncatedStreamError: If the stream ends before a valid final record.
        CryptoFileError: If reading the encrypted stream fails.
    """
    if not hasattr(src_stream, "read") or not callable(src_stream.read):
        raise ValidationError("The source stream must have a 'read' method.")

    if not isinstance(password, (str, bytes)):
        raise ValidationError("The password must be of type 'str' or 'bytes'.")
    if isinstance(password, str) and any(
        0xD800 <= ord(character) <= 0xDFFF for character in password
    ):
        raise ValidationError("The password cannot be encoded in UTF-8.")

    if (
        default_config.MAX_CHUNK_SIZE <= 0
        or default_config.MAX_CHUNK_SIZE > ABSOLUTE_MAX_CHUNK_SIZE
    ):
        raise ValidationError("Maximum limit for invalid chunks in the configuration.")

    try:
        header_size = _HEADER_STRUCT.size
        header = _read_up_to(src_stream, header_size)
        if len(header) < header_size:
            raise HeaderError("The stream is too short to contain a valid header.")

        (
            magic,
            salt,
            time_cost,
            memory_cost,
            parallelism,
            chunk_size,
            nonce_base,
        ) = _HEADER_STRUCT.unpack(header)

        if magic != _FORMAT_MAGIC:
            raise UnsupportedVersionError("Unsupported version or magic ID.")
        pwd_bytes = _password_bytes(password)
        if not pwd_bytes:
            raise ValidationError("The password must not be empty.")

        test_profile = default_config.KDF_PROFILE == KDFProfile.TEST
        if (
            time_cost <= 0
            or memory_cost < 8 * parallelism
            or parallelism <= 0
            or (
                not test_profile
                and (
                    memory_cost < 64 * 1024
                    or time_cost < 3
                    or parallelism < 4
                )
            )
            or memory_cost > min(default_config.MAX_MEMORY_COST, MAX_KDF_MEMORY_COST)
            or time_cost > min(default_config.MAX_TIME_COST, MAX_KDF_TIME_COST)
            or parallelism > min(default_config.MAX_PARALLELISM, MAX_KDF_PARALLELISM)
        ):
            raise HeaderError("Argon2id header parameters are outside the permitted security limits.")

        if (
            chunk_size <= 0
            or chunk_size > default_config.MAX_CHUNK_SIZE
            or chunk_size > ABSOLUTE_MAX_CHUNK_SIZE
        ):
            raise HeaderError("Chunk size read from the invalid header.")

        derivator = KeyDerivator(
            length=32,
            memory_cost=memory_cost,
            time_cost=time_cost,
            parallelism=parallelism,
            profile=KDFProfile.TEST if test_profile else KDFProfile.DECRYPTION,
            max_memory_cost=min(default_config.MAX_MEMORY_COST, MAX_KDF_MEMORY_COST),
            max_time_cost=min(default_config.MAX_TIME_COST, MAX_KDF_TIME_COST),
            max_parallelism=min(default_config.MAX_PARALLELISM, MAX_KDF_PARALLELISM),
        )
        key = derivator.derive(pwd_bytes, salt)

        cipher = AESCipher()
        counter = 0
        encrypted_chunk_size = chunk_size + TAG_SIZE
        
        encrypted_chunk = _read_up_to(src_stream, encrypted_chunk_size)
        final_block_verified = False
        is_last_block = False

        if not encrypted_chunk:
            raise TruncatedStreamError("The stream does not contain any data blocks.")

        while not is_last_block:
            next_encrypted_chunk = _read_up_to(src_stream, encrypted_chunk_size)
            if not next_encrypted_chunk:
                is_last_block = True

            if len(encrypted_chunk) < TAG_SIZE:
                raise IntegrityError("The cipher block is too short to hold the authentication tag.")

            ciphertext_body = encrypted_chunk[:-TAG_SIZE]
            tag = encrypted_chunk[-TAG_SIZE:]
            full_ciphertext = ciphertext_body + tag

            end_flag = 0x01 if is_last_block else 0x00
            n = len(ciphertext_body)

            # Authenticate record position and finality so valid records cannot
            # be reordered or silently removed while retaining valid tags.
            nonce = _NONCE_STRUCT.pack(nonce_base, counter)
            aad = _record_aad(header, counter, end_flag, n)

            try:
                plaintext = cipher.decrypt(key, nonce, full_ciphertext, associated_data=aad)
            except Exception as e:
                raise IntegrityError("GCM authentication failed: corrupted data or incorrect password.") from e

            if is_last_block:
                final_block_verified = True

            yield plaintext

            encrypted_chunk = next_encrypted_chunk
            counter += 1

        if not final_block_verified:
            raise TruncatedStreamError("The stream was interrupted before reaching the end marker.")

    except (OSError, IOError) as e:
        raise CryptoFileError("I/O error while reading the encrypted stream.") from e
    except CryptoError:
        raise
    except Exception as e:
        raise ValidationError(f"Unexpected error during decryption: {e}") from e
