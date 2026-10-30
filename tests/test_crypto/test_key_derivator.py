import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from crypto.key_derivator import KeyDerivator


PASSWORD = "mot de passe de test"
SALT = b"salt de test 1234"


@pytest.fixture
def derivator():
    return KeyDerivator(memory_cost=8 * 1024, time_cost=1, parallelism=1)


def test_same_password_and_salt_produce_same_key(derivator):
    assert derivator.derive(PASSWORD, SALT) == derivator.derive(PASSWORD, SALT)


def test_different_passwords_produce_different_keys(derivator):
    assert derivator.derive(PASSWORD, SALT) != derivator.derive("autre mot de passe", SALT)


def test_different_salts_produce_different_keys(derivator):
    assert derivator.derive(PASSWORD, SALT) != derivator.derive(PASSWORD, b"another salt 123")


@pytest.mark.parametrize("length", [4, 16, 32, 64])
def test_derived_key_has_requested_length(length):
    key = KeyDerivator(
        length=length,
        memory_cost=8 * 1024,
        time_cost=1,
        parallelism=1,
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
    first_key = derivator.derive("", SALT)

    assert isinstance(first_key, bytes)
    assert first_key == derivator.derive("", SALT)
    assert len(first_key) == derivator.length


@pytest.mark.parametrize(
    ("password", "password_bytes"),
    [
        ("été", "été".encode("utf-8")),
        ("", b""),
        ("password" * 128, ("password" * 128).encode("utf-8")),
    ],
)
def test_string_password_matches_utf8_bytes(derivator, password, password_bytes):
    assert derivator.derive(password, SALT) == derivator.derive(password_bytes, SALT)


def test_visually_equivalent_unicode_passwords_are_not_normalized(derivator):
    composed = "é"
    decomposed = "e\u0301"

    assert composed != decomposed
    assert derivator.derive(composed, SALT) != derivator.derive(decomposed, SALT)


@pytest.mark.parametrize(
    "password",
    [
        "plain ASCII",
        "mot de passe avec accents éàù",
        "密碼🔐",
        "very-long-password-" * 128,
        b"bytes password",
    ],
)
def test_supported_passwords_produce_keys(derivator, password):
    key = derivator.derive(password, SALT)

    assert isinstance(key, bytes)
    assert len(key) == derivator.length


@pytest.mark.parametrize("password", [None, 42])
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
    derivator = KeyDerivator(**settings)
    expected = Argon2id(
        salt=SALT,
        length=settings["length"],
        iterations=settings["time_cost"],
        lanes=settings["parallelism"],
        memory_cost=settings["memory_cost"],
    ).derive(PASSWORD.encode("utf-8"))

    assert derivator.derive(PASSWORD, SALT) == expected


def test_fixed_argon2id_vector():
    derivator = KeyDerivator(
        length=32,
        memory_cost=32,
        time_cost=3,
        parallelism=4,
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
    derivator = KeyDerivator(**parameters)

    with pytest.raises(ValueError):
        derivator.derive(PASSWORD, SALT)


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
    other_key = derivator.derive("different password", SALT)

    assert first_key != other_key
    assert derivator.derive(PASSWORD, SALT) == first_key


def test_concurrent_calls_are_deterministic(derivator):
    with ThreadPoolExecutor(max_workers=4) as executor:
        keys = list(executor.map(lambda _: derivator.derive(PASSWORD, SALT), range(4)))

    assert keys == [keys[0]] * 4

