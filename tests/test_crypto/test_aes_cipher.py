import pytest
import secrets
from crypto.aes_cipher import AESCipher
from crypto.exceptions import IntegrityError, ValidationError
from crypto.key_derivator import KeyDerivator
from crypto.encryption_orchestrator import EncryptionOrchestrator


KEY = b"0123456789abcdef0123456789abcdef"
NONCE = b"012345678901"


@pytest.fixture
def cipher():
	return AESCipher()


def test_encrypt_then_decrypt(cipher):
	data = b"message a chiffrer"
	encrypted = cipher.encrypt(KEY, NONCE, data)
	assert cipher.decrypt(KEY, NONCE, encrypted) == data


def test_empty_data(cipher):
	encrypted = cipher.encrypt(KEY, NONCE, b"")
	assert cipher.decrypt(KEY, NONCE, encrypted) == b""


@pytest.mark.parametrize("size", [1024 * 1024, 10 * 1024 * 1024])
def test_big_data(cipher, size):
	data = secrets.token_bytes(size)
	assert cipher.decrypt(KEY, NONCE, cipher.encrypt(KEY, NONCE, data)) == data


def test_arbitrary_bytes(cipher):
	data = bytes(range(256))
	assert cipher.decrypt(KEY, NONCE, cipher.encrypt(KEY, NONCE, data)) == data


def test_wrong_key_fails(cipher):
	encrypted = cipher.encrypt(KEY, NONCE, b"secret")
	with pytest.raises(IntegrityError):
		cipher.decrypt(b"fedcba9876543210fedcba9876543210", NONCE, encrypted)


@pytest.mark.parametrize("invalid_key", [
    b"",
    b"short",
    b"0123456789abcdef0123456789abcdef0"
])
def test_invalid_key_length_raises(cipher, invalid_key):
    with pytest.raises(ValidationError):
        cipher.encrypt(invalid_key, NONCE, b"secret")


@pytest.mark.parametrize("invalid_key", [None, "0123456789abcdef", bytearray(KEY)])
def test_encrypt_rejects_non_bytes_key(cipher, invalid_key):
    with pytest.raises(ValidationError, match="AES key must be bytes."):
        cipher.encrypt(invalid_key, NONCE, b"secret")


@pytest.mark.parametrize("invalid_nonce", [None, "012345678901", bytearray(NONCE)])
def test_encrypt_rejects_non_bytes_nonce(cipher, invalid_nonce):
    with pytest.raises(ValidationError, match="Nonce must be bytes."):
        cipher.encrypt(KEY, invalid_nonce, b"secret")


@pytest.mark.parametrize("invalid_data", [None, "secret", bytearray(b"secret")])
def test_encrypt_rejects_non_bytes_data(cipher, invalid_data):
    with pytest.raises(ValidationError, match="Data must be bytes."):
        cipher.encrypt(KEY, NONCE, invalid_data)


@pytest.mark.parametrize("invalid_associated_data", ["metadata", bytearray(b"metadata")])
def test_encrypt_rejects_non_bytes_associated_data(cipher, invalid_associated_data):
    with pytest.raises(ValidationError, match="Associated data must be bytes or None."):
        cipher.encrypt(KEY, NONCE, b"secret", associated_data=invalid_associated_data)


def test_wrong_nonce_fails(cipher):
	encrypted = cipher.encrypt(KEY, NONCE, b"secret")
	equivalent_but_different_nonce = b"111111111111"
	with pytest.raises(IntegrityError, match="Decryption impossible"):
		cipher.decrypt(KEY, equivalent_but_different_nonce, encrypted)


@pytest.mark.parametrize("invalid_nonce", [
    b"",
    b"short",
    b"0123456789abcdef"
])
def test_invalid_nonce_length_raises(cipher, invalid_nonce):
    error_message = "Nonce length is not optimal."
    with pytest.raises(ValidationError, match=error_message):
        cipher.encrypt(KEY, invalid_nonce, b"secret")


def test_nonce_reuse_is_security_risk(cipher):
    data = b"plaintext"
    first = cipher.encrypt(KEY, NONCE, data)
    second = cipher.encrypt(KEY, NONCE, data)
    assert first == second
    assert cipher.decrypt(KEY, NONCE, first) == data
    assert cipher.decrypt(KEY, NONCE, second) == data


def test_orchestrator_generates_distinct_nonces_by_default():
    orchestrator = EncryptionOrchestrator(KeyDerivator(), AESCipher())

    password = "motdepasse"
    data = b"secret"

    first = orchestrator.encrypt(password, data)
    second = orchestrator.encrypt(password, data)

    assert first["nonce"] != second["nonce"]


def test_modified_ciphertext_fails(cipher):
	encrypted = bytearray(cipher.encrypt(KEY, NONCE, b"secret"))
	encrypted[0] ^= 1
	with pytest.raises(IntegrityError):
		cipher.decrypt(KEY, NONCE, bytes(encrypted))


def test_modified_nonce_fails(cipher):
	encrypted = cipher.encrypt(KEY, NONCE, b"secret")
	nonce = bytearray(NONCE)
	nonce[0] ^= 1
	with pytest.raises(IntegrityError, match="Decryption impossible"):
		cipher.decrypt(KEY, bytes(nonce), encrypted)


def test_unique_nonces_produce_different_ciphertexts(cipher):
	data = b"plaintext"
	assert cipher.encrypt(KEY, NONCE, data) != cipher.encrypt(KEY, b"987654321098", data)


def test_nonce_reuse_with_decrypt(cipher):
	data = b"plaintext"
	first = cipher.encrypt(KEY, NONCE, data)
	second = cipher.encrypt(KEY, NONCE, data)
	assert first == second
	assert cipher.decrypt(KEY, NONCE, first) == data
	assert cipher.decrypt(KEY, NONCE, second) == data


def test_decrypt_invalid_nonce_length_raises(cipher):
	encrypted = cipher.encrypt(KEY, NONCE, b"secret")
	error_message = "Nonce length is not optimal."
	for invalid_nonce in [b"", b"short", b"0123456789abcdef"]:
		with pytest.raises(ValidationError, match=error_message):
			cipher.decrypt(KEY, invalid_nonce, encrypted)


@pytest.mark.parametrize("invalid_key", [None, "0123456789abcdef", bytearray(KEY)])
def test_decrypt_rejects_non_bytes_key(cipher, invalid_key):
	encrypted = cipher.encrypt(KEY, NONCE, b"secret")
	with pytest.raises(ValidationError, match="AES key must be bytes."):
		cipher.decrypt(invalid_key, NONCE, encrypted)


@pytest.mark.parametrize("invalid_nonce", [None, "012345678901", bytearray(NONCE)])
def test_decrypt_rejects_non_bytes_nonce(cipher, invalid_nonce):
	encrypted = cipher.encrypt(KEY, NONCE, b"secret")
	with pytest.raises(ValidationError, match="Nonce must be bytes."):
		cipher.decrypt(KEY, invalid_nonce, encrypted)


@pytest.mark.parametrize("invalid_ciphertext", [None, "ciphertext", bytearray(b"ciphertext")])
def test_decrypt_rejects_non_bytes_ciphertext(cipher, invalid_ciphertext):
	with pytest.raises(ValidationError, match="Ciphertext must be bytes."):
		cipher.decrypt(KEY, NONCE, invalid_ciphertext)


@pytest.mark.parametrize("invalid_associated_data", ["metadata", bytearray(b"metadata")])
def test_decrypt_rejects_non_bytes_associated_data(cipher, invalid_associated_data):
	encrypted = cipher.encrypt(KEY, NONCE, b"secret")
	with pytest.raises(ValidationError, match="Associated data must be bytes or None."):
		cipher.decrypt(KEY, NONCE, encrypted, associated_data=invalid_associated_data)


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_valid_aes_key_sizes(cipher, key_size):
	key = secrets.token_bytes(key_size)
	data = b"test data with key size: " + str(key_size).encode()
	encrypted = cipher.encrypt(key, NONCE, data)
	assert cipher.decrypt(key, NONCE, encrypted) == data
	assert isinstance(encrypted, bytes)


@pytest.mark.parametrize("key_size", [0, 8, 15, 17, 31, 33, 64])
def test_invalid_aes_key_sizes(cipher, key_size):
	key = secrets.token_bytes(key_size)
	with pytest.raises(ValidationError):
		cipher.encrypt(key, NONCE, b"test")


def test_encrypt_is_deterministic_with_same_inputs(cipher):
	data = b"plaintext deterministic"
	enc1 = cipher.encrypt(KEY, NONCE, data)
	enc2 = cipher.encrypt(KEY, NONCE, data)
	assert enc1 == enc2


def test_encrypt_returns_bytes(cipher):
	result = cipher.encrypt(KEY, NONCE, b"test")
	assert isinstance(result, bytes)
	assert len(result) > 0


def test_decrypt_returns_bytes(cipher):
	encrypted = cipher.encrypt(KEY, NONCE, b"test data")
	result = cipher.decrypt(KEY, NONCE, encrypted)
	assert isinstance(result, bytes)


def test_corrupted_ciphertext_fails_at_any_position(cipher):
	encrypted = bytearray(cipher.encrypt(KEY, NONCE, b"secret message"))
	
	positions_to_test = min(len(encrypted), max(5, len(encrypted) // 10))
	for i in range(positions_to_test):
		corrupted = bytearray(encrypted)
		corrupted[i] ^= 1  # Flip un bit
		with pytest.raises(IntegrityError, match="Decryption impossible"):
			cipher.decrypt(KEY, NONCE, bytes(corrupted))


def test_data_with_null_bytes(cipher):
	data = b"\x00\x01\x02\x00test\x00end\x00"
	encrypted = cipher.encrypt(KEY, NONCE, data)
	decrypted = cipher.decrypt(KEY, NONCE, encrypted)
	assert decrypted == data


def test_data_exactly_16_bytes(cipher):
	data = b"0123456789abcdef"  # 16 bytes
	encrypted = cipher.encrypt(KEY, NONCE, data)
	assert cipher.decrypt(KEY, NONCE, encrypted) == data


def test_ciphertext_too_short_fails(cipher):
	with pytest.raises(IntegrityError, match="Decryption impossible"):
		cipher.decrypt(KEY, NONCE, b"tiny")


@pytest.mark.timeout(30)
def test_encrypt_big_data_with_timeout(cipher):
	data = secrets.token_bytes(10 * 1024 * 1024)
	encrypted = cipher.encrypt(KEY, NONCE, data)
	assert cipher.decrypt(KEY, NONCE, encrypted) == data


@pytest.mark.timeout(30)
def test_decrypt_big_data_with_timeout(cipher):
	data = secrets.token_bytes(10 * 1024 * 1024)
	encrypted = cipher.encrypt(KEY, NONCE, data)
	decrypted = cipher.decrypt(KEY, NONCE, encrypted)
	assert decrypted == data
