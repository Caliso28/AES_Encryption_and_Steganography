import base64
import secrets

import pytest

from crypto.aes_cipher import AESCipher
from crypto.encryption_orchestrator import EncryptionOrchestrator
from crypto.exceptions import IntegrityError, ValidationError
from crypto.key_derivator import KeyDerivator


PASSWORD = "mot de passe de test"


@pytest.fixture
def orchestrator():
    return EncryptionOrchestrator(
        KeyDerivator(memory_cost=8 * 1024, time_cost=1, parallelism=1),
        AESCipher(),
    )


def test_encrypt_then_decrypt_recovers_original_data(orchestrator):
    data = b"message a chiffrer"

    encrypted = orchestrator.encrypt(PASSWORD, data)

    assert orchestrator.decrypt(PASSWORD, encrypted) == data


def test_wrong_password_raises_integrity_error(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"secret")

    with pytest.raises(IntegrityError):
        orchestrator.decrypt("mauvais mot de passe", encrypted)


def test_modified_ciphertext_raises_value_error(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"secret")
    ciphertext = bytearray(base64.b64decode(encrypted["ciphertext"]))
    ciphertext[0] ^= 1
    encrypted["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

    with pytest.raises(IntegrityError):
        orchestrator.decrypt(PASSWORD, encrypted)


def test_modified_salt_raises_value_error(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"secret")
    salt = bytearray(base64.b64decode(encrypted["salt"]))
    salt[0] ^= 1
    encrypted["salt"] = base64.b64encode(salt).decode("ascii")

    with pytest.raises(IntegrityError):
        orchestrator.decrypt(PASSWORD, encrypted)


def test_modified_nonce_raises_value_error(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"secret")
    nonce = bytearray(base64.b64decode(encrypted["nonce"]))
    nonce[0] ^= 1
    encrypted["nonce"] = base64.b64encode(nonce).decode("ascii")

    with pytest.raises(IntegrityError):
        orchestrator.decrypt(PASSWORD, encrypted)


def test_empty_data_round_trips(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"")

    assert orchestrator.decrypt(PASSWORD, encrypted) == b""


def test_large_data_round_trips(orchestrator):
    data = secrets.token_bytes(10 * 1024 * 1024)

    encrypted = orchestrator.encrypt(PASSWORD, data)

    assert orchestrator.decrypt(PASSWORD, encrypted) == data


def test_encrypt_returns_expected_fields(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")

    assert set(encrypted) == {"salt", "nonce", "ciphertext"}


@pytest.mark.parametrize("field", ["salt", "nonce", "ciphertext"])
def test_encrypt_fields_are_valid_base64(orchestrator, field):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")

    assert isinstance(base64.b64decode(encrypted[field], validate=True), bytes)


def test_encryptions_with_same_inputs_are_different(orchestrator):
    first = orchestrator.encrypt(PASSWORD, b"same data")
    second = orchestrator.encrypt(PASSWORD, b"same data")

    assert first["salt"] != second["salt"]
    assert first["nonce"] != second["nonce"]
    assert first != second


@pytest.mark.parametrize("field", ["salt", "nonce", "ciphertext"])
def test_missing_encrypted_field_is_rejected(orchestrator, field):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")
    del encrypted[field]

    with pytest.raises(ValidationError, match="fields.*missing"):
        orchestrator.decrypt(PASSWORD, encrypted)


@pytest.mark.parametrize("malformed", ["%%%", "not base64!", "a"])
def test_malformed_base64_is_rejected(orchestrator, malformed):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")
    encrypted["ciphertext"] = malformed

    with pytest.raises(ValidationError, match="invalid Base64 encoding"):
        orchestrator.decrypt(PASSWORD, encrypted)


def test_non_string_base64_field_is_rejected(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")
    encrypted["salt"] = b"not a string"

    with pytest.raises(ValidationError, match="must be in Base64"):
        orchestrator.decrypt(PASSWORD, encrypted)


def test_non_dictionary_encrypted_data_is_rejected(orchestrator):
    with pytest.raises(ValidationError, match="dictionary"):
        orchestrator.decrypt(PASSWORD, ["not", "a", "dictionary"])


@pytest.mark.parametrize("password", [None, 123, b"password"])
def test_invalid_password_type_raises_validation_error(orchestrator, password):
    with pytest.raises(ValidationError, match="password"):
        orchestrator.encrypt(password, b"data")


def test_invalid_data_type_raises_validation_error(orchestrator):
    with pytest.raises(ValidationError, match="byte.*type"):
        orchestrator.encrypt(PASSWORD, "not bytes")


def test_unencodable_password_raises_validation_error(orchestrator):
    with pytest.raises(ValidationError, match="UTF-8"):
        orchestrator.encrypt("\ud800", b"data")


def test_invalid_salt_length_raises_validation_error(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")
    encrypted["salt"] = base64.b64encode(b"short").decode("ascii")

    with pytest.raises(ValidationError):
        orchestrator.decrypt(PASSWORD, encrypted)


def test_invalid_nonce_length_raises_validation_error(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")
    encrypted["nonce"] = base64.b64encode(b"short").decode("ascii")

    with pytest.raises(ValidationError):
        orchestrator.decrypt(PASSWORD, encrypted)


def test_unexpected_key_derivation_error_is_wrapped(orchestrator, monkeypatch):
    def fail_derive(*args, **kwargs):
        raise RuntimeError("private dependency detail")

    monkeypatch.setattr(orchestrator.key_derivator, "derive", fail_derive)

    with pytest.raises(ValidationError) as error:
        orchestrator.encrypt(PASSWORD, b"data")

    assert isinstance(error.value.__cause__, RuntimeError)
    assert "private dependency detail" not in str(error.value)


def test_unexpected_aes_decryption_error_is_wrapped(orchestrator, monkeypatch):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")

    def fail_decrypt(*args, **kwargs):
        raise RuntimeError("private dependency detail")

    monkeypatch.setattr(orchestrator.aes_cipher, "decrypt", fail_decrypt)

    with pytest.raises(IntegrityError) as error:
        orchestrator.decrypt(PASSWORD, encrypted)

    assert isinstance(error.value.__cause__, RuntimeError)
    assert "private dependency detail" not in str(error.value)


def test_reused_nonce_is_rejected_before_second_encryption(orchestrator, monkeypatch):
    fixed_values = {
        16: b"s" * 16,
        12: b"n" * 12,
    }
    monkeypatch.setattr(
        "crypto.encryption_orchestrator.secrets.token_bytes",
        lambda size: fixed_values[size],
    )
    orchestrator.encrypt(PASSWORD, b"first")

    with pytest.raises(ValidationError, match="Nonce already used"):
        orchestrator.encrypt(PASSWORD, b"second")


def test_same_nonce_is_allowed_for_different_keys(orchestrator, monkeypatch):
    fixed_values = {
        16: iter([b"s" * 16, b"t" * 16]),
        12: iter([b"n" * 12, b"n" * 12]),
    }

    def fake_token_bytes(size):
        return next(fixed_values[size])

    monkeypatch.setattr("crypto.encryption_orchestrator.secrets.token_bytes", fake_token_bytes)

    first = orchestrator.encrypt(PASSWORD, b"first")
    second = orchestrator.encrypt(PASSWORD, b"second")

    assert first["salt"] != second["salt"]
    assert first["nonce"] == second["nonce"]
    assert orchestrator.decrypt(PASSWORD, first) == b"first"
    assert orchestrator.decrypt(PASSWORD, second) == b"second"


def test_extra_fields_are_ignored_during_decrypt(orchestrator):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")
    encrypted["debug"] = "ignored"

    assert orchestrator.decrypt(PASSWORD, encrypted) == b"data"


def test_unexpected_aes_encrypt_error_is_wrapped(orchestrator, monkeypatch):
    def fail_encrypt(*args, **kwargs):
        raise RuntimeError("private dependency detail")

    monkeypatch.setattr(orchestrator.aes_cipher, "encrypt", fail_encrypt)

    with pytest.raises(ValidationError) as error:
        orchestrator.encrypt(PASSWORD, b"data")

    assert isinstance(error.value.__cause__, RuntimeError)
    assert "private dependency detail" not in str(error.value)


def test_unexpected_key_derivation_error_is_wrapped_on_decrypt(orchestrator, monkeypatch):
    encrypted = orchestrator.encrypt(PASSWORD, b"data")

    def fail_derive(*args, **kwargs):
        raise RuntimeError("private dependency detail")

    monkeypatch.setattr(orchestrator.key_derivator, "derive", fail_derive)

    with pytest.raises(ValidationError) as error:
        orchestrator.decrypt(PASSWORD, encrypted)

    assert isinstance(error.value.__cause__, RuntimeError)
    assert "private dependency detail" not in str(error.value)
