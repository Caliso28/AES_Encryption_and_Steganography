import io
import struct
from dataclasses import replace

import pytest

from config import (
    ABSOLUTE_MAX_CHUNK_SIZE,
    Crypto,
    KDFProfile,
    MAX_KDF_MEMORY_COST,
    NONCE_BASE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
)
from crypto.exceptions import (
    CryptoFileError,
    HeaderError,
    IntegrityError,
    TruncatedStreamError,
    UnsupportedVersionError,
    ValidationError,
)
from crypto.aes_cipher import AESCipher
from crypto.key_derivator import KeyDerivator
from crypto.password_utils import prepare_password
from crypto.stream_crypto import _record_aad, decrypt_stream, encrypt_stream


PASSWORD = "mot de passe de test"


def test_format_sizes_are_fixed_constants():
    assert (SALT_SIZE, NONCE_BASE_SIZE, TAG_SIZE) == (16, 4, 16)

    with pytest.raises(TypeError):
        Crypto(TAG_SIZE=32)


@pytest.fixture
def config():
    return Crypto(
        CHUNK_SIZE=32,
        MEMORY_COST=8 * 1024,
        TIME_COST=1,
        PARALLELISM=1,
        KDF_PROFILE=KDFProfile.TEST,
    )


def encrypt(
    data: bytes,
    password: str | bytes = PASSWORD,
    config: Crypto | None = None,
) -> bytes:
    effective_config = config or Crypto(
        CHUNK_SIZE=32,
        MEMORY_COST=8 * 1024,
        TIME_COST=1,
        PARALLELISM=1,
        KDF_PROFILE=KDFProfile.TEST,
    )
    return b"".join(encrypt_stream(io.BytesIO(data), password, effective_config))


def test_new_stream_uses_crp1(config):
    encrypted = encrypt(b"secret", config=config)

    assert encrypted[:4] == b"CRP1"


def test_record_aad_uses_exact_header_and_big_endian_metadata():
    header = b"CRP1" + bytes(range(36))
    metadata = struct.pack(">QBI", 2, 0x01, 7)

    assert _record_aad(
        header,
        2,
        0x01,
        7,
    ) == b"CRP1-RECORD\x00" + header + metadata


def test_password_preparation_normalizes_then_encodes():
    composed = prepare_password("caf\u00e9")
    decomposed = prepare_password("cafe\u0301")

    assert composed == decomposed == b"caf\xc3\xa9"


@pytest.mark.parametrize("password", [None, 42, b"password"])
def test_password_preparation_rejects_non_string_values(password):
    with pytest.raises(ValidationError, match="password"):
        prepare_password(password)


@pytest.mark.parametrize("data", [b"", b"a", b"x" * 31, b"x" * 32, b"x" * 33, b"x" * 97])
def test_stream_round_trip_across_chunk_boundaries(config, data):
    encrypted = b"".join(encrypt_stream(io.BytesIO(data), PASSWORD, config))

    assert len(encrypted[:40]) == 40
    assert b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config)) == data


@pytest.mark.parametrize("password", [PASSWORD, PASSWORD.encode("utf-8")])
def test_stream_round_trip_accepts_string_and_bytes_passwords(config, password):
    encrypted = b"".join(encrypt_stream(io.BytesIO(b"secret"), password, config))

    assert b"".join(decrypt_stream(io.BytesIO(encrypted), password, config)) == b"secret"


@pytest.mark.parametrize(
    ("encryption_password", "decryption_password"),
    [
        ("caf\u00e9", "caf\u00e9"),
        ("cafe\u0301", "cafe\u0301"),
        ("caf\u00e9", "cafe\u0301"),
        ("cafe\u0301", "caf\u00e9"),
    ],
)
def test_stream_normalizes_unicode_passwords(
    config, encryption_password, decryption_password
):
    encrypted = encrypt(
        b"Unicode password",
        encryption_password,
        config,
    )

    assert b"".join(
        decrypt_stream(io.BytesIO(encrypted), decryption_password, config)
    ) == b"Unicode password"


def test_wrong_password_is_rejected(config):
    encrypted = encrypt(b"secret", config=config)

    with pytest.raises(IntegrityError):
        b"".join(decrypt_stream(io.BytesIO(encrypted), "incorrect", config))


def test_modified_ciphertext_is_rejected(config):
    encrypted = bytearray(encrypt(b"secret", config=config))
    encrypted[40] ^= 1

    with pytest.raises(IntegrityError):
        b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config))


def test_truncated_final_ciphertext_is_rejected(config):
    encrypted = encrypt(b"x" * 40, config=config)[:-1]

    with pytest.raises(IntegrityError):
        b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config))


def test_truncated_header_raises_header_error(config):
    with pytest.raises(HeaderError):
        b"".join(decrypt_stream(io.BytesIO(b"short"), PASSWORD, config))


def test_unsupported_magic_bytes_are_rejected(config):
    encrypted = bytearray(encrypt(b"secret", config=config))
    encrypted[:4] = b"BAD!"

    with pytest.raises(UnsupportedVersionError):
        b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config))


@pytest.mark.parametrize(
    ("time_cost", "memory_cost", "parallelism"),
    [
        (11, 8 * 1024, 1),
        (1, MAX_KDF_MEMORY_COST + 1, 1),
        (1, 1024 * 1024, 1),
        (1, 8 * 1024, 17),
    ],
)
def test_unsafe_kdf_parameters_in_header_are_rejected(
    config, time_cost, memory_cost, parallelism
):
    header = struct.pack(
        ">4s16sIIII4s",
        config.MAGIC_BYTES,
        b"s" * 16,
        time_cost,
        memory_cost,
        parallelism,
        config.CHUNK_SIZE,
        b"n" * 4,
    )

    with pytest.raises(HeaderError, match="outside the permitted security limits"):
        b"".join(decrypt_stream(io.BytesIO(header), PASSWORD, config))


@pytest.mark.parametrize(
    ("time_cost", "memory_cost", "parallelism"),
    [(0, 8 * 1024, 1), (1, 0, 1), (1, 8 * 1024, 0), (1, 8, 2)],
)
def test_invalid_kdf_parameters_in_header_are_rejected(
    config, time_cost, memory_cost, parallelism
):
    header = struct.pack(
        ">4s16sIIII4s",
        config.MAGIC_BYTES,
        b"s" * 16,
        time_cost,
        memory_cost,
        parallelism,
        config.CHUNK_SIZE,
        b"n" * 4,
    )

    with pytest.raises(HeaderError, match="Argon2id"):
        b"".join(decrypt_stream(io.BytesIO(header), PASSWORD, config))


def test_zero_chunk_size_in_header_is_rejected(config):
    header = struct.pack(
        ">4s16sIIII4s",
        config.MAGIC_BYTES,
        b"s" * 16,
        config.TIME_COST,
        config.MEMORY_COST,
        config.PARALLELISM,
        0,
        b"n" * 4,
    )

    with pytest.raises(HeaderError, match="Chunk size"):
        b"".join(decrypt_stream(io.BytesIO(header), PASSWORD, config))


def test_chunk_size_above_configured_maximum_is_rejected_before_body_read(config):
    header = struct.pack(
        ">4s16sIIII4s",
        config.MAGIC_BYTES,
        b"s" * 16,
        config.TIME_COST,
        config.MEMORY_COST,
        config.PARALLELISM,
        config.MAX_CHUNK_SIZE + 1,
        b"n" * 4,
    )

    class TrackingStream(io.BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.read_sizes = []

        def read(self, size: int | None = -1) -> bytes:
            self.read_sizes.append(size)
            return super().read(size)

    stream = TrackingStream(header + b"unread body")

    with pytest.raises(HeaderError, match="Chunk size"):
        b"".join(decrypt_stream(stream, PASSWORD, config))

    assert stream.read_sizes == [40]


def test_encryption_chunk_size_above_configured_maximum_is_rejected(config):
    invalid_config = replace(
        config,
        CHUNK_SIZE=config.MAX_CHUNK_SIZE + 1,
    )

    with pytest.raises(ValidationError, match="Invalid chunk size"):
        b"".join(encrypt_stream(io.BytesIO(b"data"), PASSWORD, invalid_config))


def test_encryption_maximum_above_absolute_limit_is_rejected(config):
    invalid_config = replace(
        config,
        MAX_CHUNK_SIZE=ABSOLUTE_MAX_CHUNK_SIZE + 1,
    )

    with pytest.raises(ValidationError, match="Invalid chunk size"):
        b"".join(encrypt_stream(io.BytesIO(b"data"), PASSWORD, invalid_config))


def test_decryption_maximum_above_absolute_limit_is_rejected(config):
    invalid_config = replace(
        config,
        MAX_CHUNK_SIZE=ABSOLUTE_MAX_CHUNK_SIZE + 1,
    )

    with pytest.raises(
        ValidationError,
        match="Maximum limit for invalid chunks in the configuration",
    ):
        b"".join(decrypt_stream(io.BytesIO(b""), PASSWORD, invalid_config))


def test_chunk_size_above_absolute_maximum_is_rejected_before_body_read(config):
    permissive_config = replace(
        config,
        MAX_CHUNK_SIZE=ABSOLUTE_MAX_CHUNK_SIZE,
    )
    header = struct.pack(
        ">4s16sIIII4s",
        config.MAGIC_BYTES,
        b"s" * 16,
        config.TIME_COST,
        config.MEMORY_COST,
        config.PARALLELISM,
        ABSOLUTE_MAX_CHUNK_SIZE + 1,
        b"n" * 4,
    )

    class TrackingStream(io.BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.read_sizes = []

        def read(self, size: int | None = -1) -> bytes:
            self.read_sizes.append(size)
            return super().read(size)

    stream = TrackingStream(header + b"unread body")

    with pytest.raises(HeaderError, match="Chunk size"):
        b"".join(decrypt_stream(stream, PASSWORD, permissive_config))

    assert stream.read_sizes == [40]


def test_low_cost_encryption_requires_explicit_test_profile(config):
    production_config = replace(config, KDF_PROFILE=KDFProfile.PRODUCTION)

    with pytest.raises(ValidationError, match="Production Argon2id parameters"):
        b"".join(
            encrypt_stream(io.BytesIO(b"data"), PASSWORD, production_config)
        )


def test_low_cost_stream_decryption_requires_test_profile(config):
    encrypted = encrypt(b"secret", config=config)
    production_config = replace(config, KDF_PROFILE=KDFProfile.PRODUCTION)

    with pytest.raises(HeaderError, match="outside the permitted security limits"):
        b"".join(
            decrypt_stream(io.BytesIO(encrypted), PASSWORD, production_config)
        )


def test_configured_maximum_chunk_size_is_accepted(config):
    bounded_config = replace(config, CHUNK_SIZE=64, MAX_CHUNK_SIZE=64)
    encrypted = b"".join(
        encrypt_stream(io.BytesIO(b"x" * 65), PASSWORD, bounded_config)
    )

    assert b"".join(
        decrypt_stream(io.BytesIO(encrypted), PASSWORD, bounded_config)
    ) == b"x" * 65


def test_stream_with_header_but_no_data_is_truncated(config):
    encrypted_header = encrypt(b"", config=config)[:40]

    with pytest.raises(TruncatedStreamError):
        b"".join(decrypt_stream(io.BytesIO(encrypted_header), PASSWORD, config))


@pytest.mark.parametrize("password", [None, 123, bytearray(b"password")])
def test_invalid_password_type_is_rejected(config, password):
    with pytest.raises(ValidationError, match="password"):
        b"".join(encrypt_stream(io.BytesIO(b"data"), password, config))

    with pytest.raises(ValidationError, match="password"):
        b"".join(decrypt_stream(io.BytesIO(b""), password, config))


def test_unencodable_password_is_rejected(config):
    with pytest.raises(ValidationError, match="UTF-8"):
        b"".join(encrypt_stream(io.BytesIO(b"data"), "\ud800", config))

    with pytest.raises(ValidationError, match="UTF-8"):
        b"".join(decrypt_stream(io.BytesIO(b""), "\ud800", config))


@pytest.mark.parametrize("stream", [None, object()])
def test_stream_without_read_method_is_rejected(config, stream):
    with pytest.raises(ValidationError, match="must have a 'read' method"):
        b"".join(encrypt_stream(stream, PASSWORD, config))

    with pytest.raises(ValidationError, match="must have a 'read' method"):
        b"".join(decrypt_stream(stream, PASSWORD, config))


def test_invalid_encryption_chunk_size_is_rejected(config):
    invalid_config = replace(config, CHUNK_SIZE=15)

    with pytest.raises(ValidationError, match="Invalid chunk size"):
        b"".join(encrypt_stream(io.BytesIO(b"data"), PASSWORD, invalid_config))


def test_stream_read_error_is_wrapped(config):
    class FailingStream(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise OSError("disk error")

    with pytest.raises(CryptoFileError, match="I/O error"):
        b"".join(encrypt_stream(FailingStream(), PASSWORD, config))

    with pytest.raises(CryptoFileError, match="I/O error"):
        b"".join(decrypt_stream(FailingStream(), PASSWORD, config))


class ShortReadStream(io.BytesIO):
    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            return super().read(size)
        return super().read(min(size, 7))


def test_stream_round_trip_handles_short_reads(config):
    plaintext = b"partial reads must not split authenticated records" * 3
    encrypted = b"".join(encrypt_stream(ShortReadStream(plaintext), PASSWORD, config))

    assert b"".join(
        decrypt_stream(ShortReadStream(encrypted), PASSWORD, config)
    ) == plaintext


@pytest.mark.parametrize(
    ("offset", "replacement"),
    [
        (4, b"t" * 16),
        (20, struct.pack(">I", 2)),
        (24, struct.pack(">I", 8 * 1024 + 8)),
        (28, struct.pack(">I", 2)),
        (32, struct.pack(">I", 31)),
        (36, b"m" * 4),
    ],
)
def test_modified_header_fields_are_rejected(config, offset, replacement):
    encrypted = bytearray(encrypt(b"x" * 64, config=config))
    encrypted[offset : offset + len(replacement)] = replacement

    with pytest.raises(IntegrityError):
        b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config))


def test_changed_chunk_size_in_header_is_authenticated(config):
    encrypted = bytearray(encrypt(b"hello", config=config))
    assert encrypted[:4] == b"CRP1"
    encrypted[32:36] = struct.pack(">I", 64)

    with pytest.raises(IntegrityError):
        b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config))


def test_crp1_record_authentication_includes_exact_header(config):
    plaintext = b"legacy"
    salt = b"s" * SALT_SIZE
    nonce_base = b"n" * 4
    header = struct.pack(
        ">4s16sIIII4s",
        b"CRP1",
        salt,
        config.TIME_COST,
        config.MEMORY_COST,
        config.PARALLELISM,
        config.CHUNK_SIZE,
        nonce_base,
    )
    key = KeyDerivator(
        length=32,
        memory_cost=config.MEMORY_COST,
        time_cost=config.TIME_COST,
        parallelism=config.PARALLELISM,
        profile=KDFProfile.TEST,
    ).derive(PASSWORD.encode("utf-8"), salt)
    aad = _record_aad(header, 0, 0x01, len(plaintext))
    ciphertext = AESCipher().encrypt(
        key,
        nonce_base + b"\x00" * 8,
        plaintext,
        associated_data=aad,
    )

    assert b"".join(decrypt_stream(io.BytesIO(header + ciphertext), PASSWORD, config)) == plaintext


def test_crp1_uses_nfc_password_normalization(config):
    password = "cafe\u0301"
    salt = b"s" * SALT_SIZE
    nonce_base = b"n" * 4
    header = struct.pack(
        ">4s16sIIII4s",
        b"CRP1",
        salt,
        config.TIME_COST,
        config.MEMORY_COST,
        config.PARALLELISM,
        config.CHUNK_SIZE,
        nonce_base,
    )
    key = KeyDerivator(
        length=32,
        memory_cost=config.MEMORY_COST,
        time_cost=config.TIME_COST,
        parallelism=config.PARALLELISM,
        profile=KDFProfile.TEST,
    ).derive(prepare_password(password), salt)
    ciphertext = AESCipher().encrypt(
        key,
        nonce_base + b"\x00" * 8,
        b"legacy",
        associated_data=_record_aad(header, 0, 0x01, 6),
    )

    assert b"".join(
        decrypt_stream(io.BytesIO(header + ciphertext), password, config)
    ) == b"legacy"
    assert b"".join(
        decrypt_stream(io.BytesIO(header + ciphertext), "caf\u00e9", config)
    ) == b"legacy"


@pytest.mark.parametrize("invalid_read", [None, "", []])
def test_non_bytes_stream_read_results_are_rejected(config, invalid_read):
    class InvalidReadStream:
        def read(self, size=-1):
            return invalid_read

    with pytest.raises(ValidationError, match="stream must return bytes"):
        b"".join(encrypt_stream(InvalidReadStream(), PASSWORD, config))

    encrypted_header = encrypt(b"", config=config)[:40]

    class InvalidBodyStream(io.BytesIO):
        def read(self, size=-1):
            if self.tell() == len(encrypted_header):
                return invalid_read
            return super().read(size)

    with pytest.raises(ValidationError, match="stream must return bytes"):
        b"".join(
            decrypt_stream(
                InvalidBodyStream(encrypted_header),
                PASSWORD,
                config,
            )
        )


def test_empty_password_is_rejected(config):
    with pytest.raises(ValidationError, match="password must not be empty"):
        b"".join(encrypt_stream(io.BytesIO(b"secret"), "", config))

    encrypted = encrypt(b"secret", config=config)
    with pytest.raises(ValidationError, match="password must not be empty"):
        b"".join(decrypt_stream(io.BytesIO(encrypted), "", config))


@pytest.mark.parametrize("offset", [40, 40 + 48, 40 + 2 * 48])
def test_modified_ciphertext_in_each_record_is_rejected(config, offset):
    encrypted = bytearray(encrypt(b"x" * 70, config=config))
    encrypted[offset] ^= 1

    with pytest.raises(IntegrityError):
        b"".join(decrypt_stream(io.BytesIO(encrypted), PASSWORD, config))


def test_reordered_records_are_rejected(config):
    encrypted = encrypt(b"x" * 64, config=config)
    header, first, second = encrypted[:40], encrypted[40:88], encrypted[88:136]

    with pytest.raises(IntegrityError):
        b"".join(
            decrypt_stream(io.BytesIO(header + second + first), PASSWORD, config)
        )


@pytest.mark.parametrize("operation", ["duplicate", "delete"])
def test_duplicated_or_deleted_record_is_rejected(config, operation):
    encrypted = encrypt(b"x" * 96, config=config)
    header = encrypted[:40]
    records = [
        encrypted[offset : offset + 48]
        for offset in range(40, len(encrypted), 48)
    ]

    if operation == "duplicate":
        tampered = header + records[0] + records[0] + b"".join(records[1:])
    else:
        tampered = header + records[0] + b"".join(records[2:])

    with pytest.raises(IntegrityError):
        b"".join(decrypt_stream(io.BytesIO(tampered), PASSWORD, config))


def test_trailing_bytes_after_final_record_are_rejected(config):
    encrypted = encrypt(b"secret", config=config)

    with pytest.raises(IntegrityError):
        b"".join(
            decrypt_stream(io.BytesIO(encrypted + b"\x00"), PASSWORD, config)
        )


@pytest.mark.parametrize("truncated_size", range(1, 16))
def test_truncated_authentication_tag_is_rejected(config, truncated_size):
    encrypted_header = encrypt(b"", config=config)[:40]

    with pytest.raises(IntegrityError):
        b"".join(
            decrypt_stream(
                io.BytesIO(encrypted_header + b"\x00" * truncated_size),
                PASSWORD,
                config,
            )
        )
