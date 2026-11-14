import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import crypto.key_derivator as key_derivator_module
from config import (
    KDFProfile,
    MAX_KDF_MEMORY_COST,
    MAX_KDF_TIME_COST,
)
from crypto.exceptions import KDFBusyError
from crypto.key_derivator import KeyDerivator


PASSWORD = b"mot de passe de test"
SALT = b"salt de test 1234"


@pytest.fixture
def derivator():
    return KeyDerivator(
        memory_cost=8 * 1024,
        time_cost=1,
        parallelism=1,
        profile=KDFProfile.TEST,
    )


def test_same_password_and_salt_produce_same_key(derivator):
    assert derivator.derive(PASSWORD, SALT) == derivator.derive(PASSWORD, SALT)


def test_different_passwords_produce_different_keys(derivator):
    assert derivator.derive(PASSWORD, SALT) != derivator.derive(b"autre mot de passe", SALT)


def test_different_salts_produce_different_keys(derivator):
    assert derivator.derive(PASSWORD, SALT) != derivator.derive(PASSWORD, b"another salt 123")


@pytest.mark.parametrize("length", [4, 16, 32, 64])
def test_derived_key_has_requested_length(length):
    key = KeyDerivator(
        length=length,
        memory_cost=8 * 1024,
        time_cost=1,
        parallelism=1,
        profile=KDFProfile.TEST,
    ).derive(PASSWORD, SALT)

    assert len(key) == length


def test_empty_salt_is_rejected(derivator):
    with pytest.raises(ValueError):
        derivator.derive(PASSWORD, b"")


@pytest.mark.parametrize("salt", [b"x", b"x" * 7])
def test_salt_shorter_than_argon2_minimum_is_rejected(derivator, salt):
    with pytest.raises(ValueError):
        derivator.derive(PASSWORD, salt)


def test_minimum_valid_salt_length_is_supported(derivator):
    key = derivator.derive(PASSWORD, b"x" * 8)

    assert len(key) == derivator.length


def test_empty_password_is_supported_and_deterministic(derivator):
    first_key = derivator.derive(b"", SALT)

    assert isinstance(first_key, bytes)
    assert first_key == derivator.derive(b"", SALT)
    assert len(first_key) == derivator.length


def test_string_password_is_rejected(derivator):
    with pytest.raises(TypeError, match="password must be bytes"):
        derivator.derive("password", SALT)


def test_key_derivator_does_not_normalize_prepared_bytes(derivator):
    composed = "é".encode("utf-8")
    decomposed = "e\u0301".encode("utf-8")

    assert composed != decomposed
    assert derivator.derive(composed, SALT) != derivator.derive(decomposed, SALT)


@pytest.mark.parametrize(
    "password",
    [
        b"plain ASCII",
        "mot de passe avec accents éàù".encode("utf-8"),
        "密碼🔐".encode("utf-8"),
        ("very-long-password-" * 128).encode("utf-8"),
        b"bytes password",
    ],
)
def test_supported_passwords_produce_keys(derivator, password):
    key = derivator.derive(password, SALT)

    assert isinstance(key, bytes)
    assert len(key) == derivator.length


@pytest.mark.parametrize("password", [None, 42, "password", bytearray(b"password")])
def test_unsupported_password_types_are_rejected(derivator, password):
    with pytest.raises(TypeError):
        derivator.derive(password, SALT)  # type: ignore[arg-type]


@pytest.mark.parametrize("salt", [None, "salt must be bytes"])
def test_unsupported_salt_types_are_rejected(derivator, salt):
    with pytest.raises(TypeError):
        derivator.derive(PASSWORD, salt)  # type: ignore[arg-type]


def test_custom_constructor_parameters_are_used():
    settings = {
        "length": 24,
        "memory_cost": 16 * 1024,
        "time_cost": 2,
        "parallelism": 2,
    }
    derivator = KeyDerivator(**settings, profile=KDFProfile.TEST)
    expected = Argon2id(
        salt=SALT,
        length=settings["length"],
        iterations=settings["time_cost"],
        lanes=settings["parallelism"],
        memory_cost=settings["memory_cost"],
    ).derive(PASSWORD)

    assert derivator.derive(PASSWORD, SALT) == expected


def test_fixed_argon2id_vector():
    derivator = KeyDerivator(
        length=32,
        memory_cost=32,
        time_cost=3,
        parallelism=4,
        profile=KDFProfile.TEST,
    )
    password = bytes([1]) * 32
    salt = bytes(range(2, 18))

    assert derivator.derive(password, salt).hex() == (
        "6619a75384cb276c10100977c96f6b0a"
        "fe4a9f1b43cc478c39cffc330fcb4ed1"
    )


@pytest.mark.parametrize(
    "settings",
    [
        {"length": 3},
        {"memory_cost": 0},
        {"time_cost": 0},
        {"parallelism": 0},
        {"memory_cost": 8, "parallelism": 2},
    ],
)
def test_invalid_argon2id_parameters_are_rejected(settings):
    parameters = {
        "length": 32,
        "memory_cost": 8,
        "time_cost": 1,
        "parallelism": 1,
    }
    parameters.update(settings)
    with pytest.raises(ValueError):
        KeyDerivator(**parameters, profile=KDFProfile.TEST)


@pytest.mark.parametrize(
    "settings",
    [
        {"memory_cost": 8 * 1024},
        {"time_cost": 1},
        {"parallelism": 1},
    ],
)
def test_weak_custom_parameters_require_test_profile(settings):
    with pytest.raises(ValueError, match="Production Argon2id"):
        KeyDerivator(**settings)


@pytest.mark.parametrize(
    "settings",
    [
        {"memory_cost": MAX_KDF_MEMORY_COST + 1},
        {"time_cost": MAX_KDF_TIME_COST + 1},
        {"parallelism": 17},
    ],
)
def test_excessive_production_parameters_are_rejected(settings):
    with pytest.raises(ValueError, match="exceeds"):
        KeyDerivator(**settings)


def test_production_resource_limits_cannot_be_raised():
    with pytest.raises(ValueError, match="cannot exceed the production ceiling"):
        KeyDerivator(max_memory_cost=MAX_KDF_MEMORY_COST + 1)


def test_decryption_profile_requires_and_enforces_resource_limits():
    with pytest.raises(ValueError, match="requires all three resource limits"):
        KeyDerivator(
            memory_cost=64 * 1024,
            time_cost=3,
            parallelism=4,
            profile=KDFProfile.DECRYPTION,
        )

    with pytest.raises(ValueError, match="exceeds"):
        KeyDerivator(
            memory_cost=64 * 1024 + 1,
            time_cost=3,
            parallelism=4,
            profile=KDFProfile.DECRYPTION,
            max_memory_cost=64 * 1024,
            max_time_cost=3,
            max_parallelism=4,
        )


def test_decryption_profile_rejects_parameters_below_production_minimums():
    with pytest.raises(ValueError, match="Decryption Argon2id parameters"):
        KeyDerivator(
            memory_cost=8 * 1024,
            time_cost=1,
            parallelism=1,
            profile=KDFProfile.DECRYPTION,
            max_memory_cost=8 * 1024,
            max_time_cost=1,
            max_parallelism=1,
        )


def test_reusing_a_salt_repeats_the_key_for_the_same_password(derivator):
    first_key = derivator.derive(PASSWORD, SALT)
    second_key = derivator.derive(PASSWORD, SALT)

    assert first_key == second_key


def test_random_salts_avoid_fixed_salt_key_repetition(derivator):
    first_key = derivator.derive(PASSWORD, secrets.token_bytes(16))
    second_key = derivator.derive(PASSWORD, secrets.token_bytes(16))

    assert first_key != second_key


def test_repeated_calls_do_not_reuse_derivation_state(derivator):
    first_key = derivator.derive(PASSWORD, SALT)
    other_key = derivator.derive(b"different password", SALT)

    assert first_key != other_key
    assert derivator.derive(PASSWORD, SALT) == first_key


def test_concurrent_calls_are_deterministic(derivator):
    with ThreadPoolExecutor(max_workers=4) as executor:
        keys = list(executor.map(lambda _: derivator.derive(PASSWORD, SALT), range(4)))

    assert keys == [keys[0]] * 4


def test_concurrent_derivations_are_serialized(monkeypatch, derivator):
    active = 0
    maximum_active = 0
    state_lock = threading.Lock()

    class TrackingArgon2id:
        def __init__(self, **kwargs):
            pass

        def derive(self, password):
            nonlocal active, maximum_active
            with state_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with state_lock:
                active -= 1
            return b"test"

    monkeypatch.setattr(key_derivator_module, "Argon2id", TrackingArgon2id)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: derivator.derive(PASSWORD, SALT), range(4)))

    assert maximum_active == 1


def test_derivation_is_rejected_when_admission_times_out(monkeypatch, derivator):
    monkeypatch.setattr(key_derivator_module, "KDF_QUEUE_TIMEOUT_SECONDS", 0.01)
    assert key_derivator_module._KDF_SEMAPHORE.acquire(blocking=False)
    try:
        with pytest.raises(KDFBusyError, match="resource admission timed out"):
            derivator.derive(PASSWORD, SALT)
    finally:
        key_derivator_module._KDF_SEMAPHORE.release()
