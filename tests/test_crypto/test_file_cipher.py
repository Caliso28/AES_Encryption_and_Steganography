from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import multiprocessing
from pathlib import Path

import pytest

from config import Crypto, KDFProfile
from crypto import file_cipher
from crypto.exceptions import CryptoFileError, IntegrityError, ValidationError
from crypto.file_cipher import decrypt_file as decrypt_file_to_path, encrypt_file
from crypto.stream_crypto import decrypt_stream, encrypt_stream


PASSWORD = "mot de passe de test"
CONFIG = Crypto(
    CHUNK_SIZE=32,
    MEMORY_COST=8 * 1024,
    TIME_COST=1,
    PARALLELISM=1,
    KDF_PROFILE=KDFProfile.TEST,
)


def _encrypt_file_with_barrier(source_path, destination, barrier, results):
    original_encrypt_stream = file_cipher.encrypt_stream
    synchronized = False

    def synchronized_encrypt_stream(*args, **kwargs):
        nonlocal synchronized
        yield from original_encrypt_stream(*args, **kwargs)
        if not synchronized:
            synchronized = True
            barrier.wait(timeout=20)

    file_cipher.encrypt_stream = synchronized_encrypt_stream
    results.put(
        str(file_cipher.encrypt_file(source_path, PASSWORD, destination, CONFIG))
    )


def decrypt_file(path, password=PASSWORD, config=CONFIG):
    with path.open("rb") as encrypted_file:
        return b"".join(decrypt_stream(encrypted_file, password, config))


def test_encrypt_file_uses_encrypted_suffix_and_round_trips(tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"contenu a chiffrer")

    result = encrypt_file(source, PASSWORD, None, CONFIG)

    assert result == tmp_path / "document_encrypted.txt"
    assert decrypt_file(result) == b"contenu a chiffrer"
    decrypted_path = decrypt_file_to_path(result, PASSWORD, config=CONFIG)
    assert decrypted_path == tmp_path / "document_decrypted.txt"
    assert decrypted_path.read_bytes() == b"contenu a chiffrer"


def test_decrypt_file_preserves_encryption_number_and_numbers_repeated_decryptions(
    tmp_path,
):
    source = tmp_path / "document.txt"
    source.write_bytes(b"contenu")
    encrypted_path = tmp_path / "document_2_encrypted.txt"
    encrypted_path.write_bytes(
        b"".join(encrypt_stream(BytesIO(source.read_bytes()), PASSWORD, CONFIG))
    )

    first = decrypt_file_to_path(encrypted_path, PASSWORD, config=CONFIG)
    second = decrypt_file_to_path(encrypted_path, PASSWORD, config=CONFIG)

    assert first == tmp_path / "document_2_decrypted.txt"
    assert second == tmp_path / "document_2_decrypted_2.txt"
    assert first.read_bytes() == second.read_bytes() == b"contenu"


def test_decrypt_file_writes_to_explicit_destination(tmp_path):
    source = tmp_path / "source.txt"
    source.write_bytes(b"contenu")
    encrypted_path = encrypt_file(source, PASSWORD, config=CONFIG)
    destination = tmp_path / "output"
    destination.mkdir()

    result = decrypt_file_to_path(encrypted_path, PASSWORD, destination, CONFIG)

    assert result == destination / "source_decrypted.txt"
    assert result.read_bytes() == b"contenu"


def test_decrypt_file_handles_empty_file(tmp_path):
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")
    encrypted_path = encrypt_file(source, PASSWORD, config=CONFIG)

    result = decrypt_file_to_path(encrypted_path, PASSWORD, config=CONFIG)

    assert result == tmp_path / "empty_decrypted.txt"
    assert result.read_bytes() == b""


def test_decrypt_file_supports_source_without_extension(tmp_path):
    source = tmp_path / "document"
    source.write_bytes(b"contenu sans extension")
    encrypted_path = encrypt_file(source, PASSWORD, config=CONFIG)

    result = decrypt_file_to_path(encrypted_path, PASSWORD, config=CONFIG)

    assert result == tmp_path / "document_decrypted"
    assert result.read_bytes() == b"contenu sans extension"


@pytest.mark.parametrize(
    ("filename", "expected_name"),
    [
        ("document_aes.txt", "document_decrypted.txt"),
        ("renamed.bin", "renamed_decrypted.bin"),
    ],
)
def test_decrypt_file_accepts_renamed_encrypted_files(
    tmp_path, filename, expected_name
):
    encrypted_path = tmp_path / filename
    encrypted_path.write_bytes(
        b"".join(encrypt_stream(BytesIO(b"contenu"), PASSWORD, CONFIG))
    )

    result = decrypt_file_to_path(encrypted_path, PASSWORD, config=CONFIG)

    assert result == tmp_path / expected_name
    assert result.read_bytes() == b"contenu"


def test_encrypt_file_handles_empty_file(tmp_path):
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")

    result = encrypt_file(source, PASSWORD, tmp_path, CONFIG)

    assert result == tmp_path / "empty_encrypted.txt"
    assert decrypt_file(result) == b""


def test_encrypt_file_writes_to_explicit_destination(tmp_path):
    source = tmp_path / "source.txt"
    destination = tmp_path / "output"
    source.write_bytes(b"contenu")
    destination.mkdir()

    result = encrypt_file(source, PASSWORD, destination, CONFIG)

    assert result.parent == destination
    assert decrypt_file(result) == b"contenu"


def test_file_cipher_uses_global_destination_by_default(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    destination = tmp_path / "output"
    source.write_bytes(b"contenu")
    destination.mkdir()
    monkeypatch.setattr("config.files.dest_path", destination)

    encrypted_path = encrypt_file(source, PASSWORD, config=CONFIG)
    decrypted_path = decrypt_file_to_path(encrypted_path, PASSWORD, config=CONFIG)

    assert encrypted_path == destination / "source_encrypted.txt"
    assert decrypted_path == destination / "source_decrypted.txt"
    assert decrypted_path.read_bytes() == b"contenu"


def test_explicit_destination_overrides_global_destination(tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    configured_destination = tmp_path / "configured"
    explicit_destination = tmp_path / "explicit"
    decrypted_destination = tmp_path / "decrypted"
    source.write_bytes(b"contenu")
    configured_destination.mkdir()
    explicit_destination.mkdir()
    decrypted_destination.mkdir()
    monkeypatch.setattr("config.files.dest_path", configured_destination)

    encrypted_path = encrypt_file(source, PASSWORD, explicit_destination, CONFIG)
    decrypted_path = decrypt_file_to_path(
        encrypted_path, PASSWORD, decrypted_destination, CONFIG
    )

    assert encrypted_path.parent == explicit_destination
    assert decrypted_path.parent == decrypted_destination
    assert decrypted_path.read_bytes() == b"contenu"


@pytest.mark.parametrize(
    ("destination", "error", "message"),
    [
        (123, ValidationError, "Invalid destination path."),
        ("missing", CryptoFileError, "Destination directory does not exist."),
        ("file", ValidationError, "Destination path must be a directory."),
    ],
)
def test_encrypt_file_validates_configured_destination(
    tmp_path, destination, error, message, monkeypatch
):
    source = tmp_path / "source.txt"
    source.write_bytes(b"source")
    if destination == "missing":
        destination = tmp_path / destination
    elif destination == "file":
        destination = tmp_path / destination
        destination.write_text("not a directory")
    monkeypatch.setattr("config.files.dest_path", destination)

    with pytest.raises(error, match=message):
        encrypt_file(source, PASSWORD, config=CONFIG)


def test_encrypt_file_defaults_to_source_directory_and_default_config(tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"contenu avec la configuration par defaut")

    result = encrypt_file(str(source), PASSWORD)

    assert result == tmp_path / "document_encrypted.txt"
    assert decrypt_file(result, config=Crypto()) == b"contenu avec la configuration par defaut"


def test_encrypt_file_numbers_existing_results(tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"second contenu")
    (tmp_path / "document_encrypted.txt").write_bytes(b"premier resultat")

    result = encrypt_file(source, PASSWORD, tmp_path, CONFIG)

    assert result == tmp_path / "document_2_encrypted.txt"
    assert decrypt_file(result) == b"second contenu"
    assert (tmp_path / "document_encrypted.txt").read_bytes() == b"premier resultat"


def test_encrypt_file_skips_all_existing_numbered_results(tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"nouveau contenu")
    (tmp_path / "document_encrypted.txt").write_bytes(b"premier resultat")
    (tmp_path / "document_2_encrypted.txt").write_bytes(b"deuxieme resultat")

    result = encrypt_file(source, PASSWORD, tmp_path, CONFIG)

    assert result == tmp_path / "document_3_encrypted.txt"
    assert decrypt_file(result) == b"nouveau contenu"


def test_encrypt_file_supports_source_without_extension(tmp_path):
    source = tmp_path / "document"
    source.write_bytes(b"contenu sans extension")

    result = encrypt_file(source, PASSWORD, tmp_path, CONFIG)

    assert result == tmp_path / "document_encrypted"
    assert decrypt_file(result) == b"contenu sans extension"


def test_encrypt_file_accepts_password_as_bytes(tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"contenu")

    result = encrypt_file(source, PASSWORD.encode("utf-8"), tmp_path, CONFIG)

    assert decrypt_file(result) == b"contenu"


def test_encrypt_file_preserves_file_created_while_output_is_being_written(
    tmp_path, monkeypatch
):
    source = tmp_path / "document.txt"
    source.write_bytes(b"source content")
    first_candidate = tmp_path / "document_encrypted.txt"
    first_candidate.write_bytes(b"created concurrently")
    original_publish = file_cipher._publish_without_overwrite
    created_during_publish = False

    def create_collision_then_publish(temporary_path, final_path):
        nonlocal created_during_publish
        if final_path == first_candidate and not created_during_publish:
            created_during_publish = True
            first_candidate.write_bytes(b"created concurrently")
        return original_publish(temporary_path, final_path)

    monkeypatch.setattr(
        file_cipher, "_publish_without_overwrite", create_collision_then_publish
    )

    result = encrypt_file(source, PASSWORD, tmp_path, CONFIG)

    assert result == tmp_path / "document_2_encrypted.txt"
    assert first_candidate.read_bytes() == b"created concurrently"
    assert decrypt_file(result) == b"source content"


def test_encrypt_file_serializes_same_output_name_concurrently(tmp_path):
    source_dirs = [tmp_path / "first", tmp_path / "second"]
    source_data = [b"first source", b"second source"]
    for source_dir, data in zip(source_dirs, source_data):
        source_dir.mkdir()
        (source_dir / "shared.txt").write_bytes(data)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda source: encrypt_file(source, PASSWORD, tmp_path, CONFIG),
                [source_dir / "shared.txt" for source_dir in source_dirs],
            )
        )

    assert {result.name for result in results} == {
        "shared_encrypted.txt",
        "shared_2_encrypted.txt",
    }
    assert {decrypt_file(result) for result in results} == set(source_data)


def test_encrypt_file_does_not_overwrite_between_processes(tmp_path):
    context = multiprocessing.get_context("spawn")
    source_dirs = [tmp_path / "first", tmp_path / "second"]
    source_data = [b"first process", b"second process"]
    for source_dir, data in zip(source_dirs, source_data):
        source_dir.mkdir()
        (source_dir / "shared.txt").write_bytes(data)

    barrier = context.Barrier(2)
    results = context.Queue()
    processes = [
        context.Process(
            target=_encrypt_file_with_barrier,
            args=(source_dir / "shared.txt", tmp_path, barrier, results),
        )
        for source_dir in source_dirs
    ]

    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=30)

        assert all(not process.is_alive() for process in processes)
        assert [process.exitcode for process in processes] == [0, 0]
        result_paths = {
            Path(results.get(timeout=1)) for _ in processes
        }
        assert {path.name for path in result_paths} == {
            "shared_encrypted.txt",
            "shared_2_encrypted.txt",
        }
        assert {decrypt_file(path) for path in result_paths} == set(source_data)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join()
        results.close()


def test_encrypt_file_removes_temporary_file_on_encryption_error(tmp_path, monkeypatch):
    source = tmp_path / "document.txt"
    source.write_bytes(b"source")
    existing_result = tmp_path / "document_encrypted.txt"
    existing_result.write_bytes(b"do not replace")

    def failing_encrypt_stream(*args, **kwargs):
        yield b"partial encrypted data"
        raise IntegrityError("encryption failed")

    monkeypatch.setattr("crypto.file_cipher.encrypt_stream", failing_encrypt_stream)

    with pytest.raises(IntegrityError, match="encryption failed"):
        encrypt_file(source, PASSWORD, tmp_path, CONFIG)

    assert existing_result.read_bytes() == b"do not replace"
    assert not (tmp_path / "document_2_encrypted.txt").exists()
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_decrypt_file_removes_temporary_file_on_decryption_error(
    tmp_path, monkeypatch
):
    encrypted_path = tmp_path / "document_encrypted.txt"
    encrypted_path.write_bytes(b"encrypted data")

    def failing_decrypt_stream(*args, **kwargs):
        yield b"partial decrypted data"
        raise IntegrityError("decryption failed")

    monkeypatch.setattr("crypto.file_cipher.decrypt_stream", failing_decrypt_stream)

    with pytest.raises(IntegrityError, match="decryption failed"):
        decrypt_file_to_path(encrypted_path, PASSWORD, config=CONFIG)

    assert not (tmp_path / "document_decrypted.txt").exists()
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


@pytest.mark.parametrize(
    "wrong_password", [True, False], ids=["wrong-password", "tampered-data"]
)
def test_decrypt_file_rejects_invalid_ciphertext_without_leaving_output(
    tmp_path, wrong_password
):
    source = tmp_path / "document.txt"
    source.write_bytes(b"contenu suffisamment long pour plusieurs blocs")
    encrypted_path = encrypt_file(source, PASSWORD, config=CONFIG)

    if not wrong_password:
        encrypted_data = bytearray(encrypted_path.read_bytes())
        encrypted_data[-1] ^= 1
        encrypted_path.write_bytes(encrypted_data)

    password = "incorrect" if wrong_password else PASSWORD
    with pytest.raises(IntegrityError):
        decrypt_file_to_path(encrypted_path, password, config=CONFIG)

    assert not (tmp_path / "document_decrypted.txt").exists()
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_encrypt_file_rejects_non_directory_destination(tmp_path):
    source = tmp_path / "source.txt"
    source.write_bytes(b"source")
    destination = tmp_path / "not-a-directory"
    destination.write_text("file")

    with pytest.raises(ValidationError, match="Destination path must be a directory."):
        encrypt_file(source, PASSWORD, destination, CONFIG)


def test_encrypt_file_rejects_missing_source(tmp_path):
    with pytest.raises(CryptoFileError, match="Path does not exist on this volume."):
        encrypt_file(tmp_path / "missing.txt", PASSWORD, tmp_path, CONFIG)


def test_encrypt_file_rejects_directory_as_source(tmp_path):
    with pytest.raises(ValidationError, match="The object isn't a file."):
        encrypt_file(tmp_path, PASSWORD, tmp_path, CONFIG)


def test_encrypt_file_rejects_missing_destination_directory(tmp_path):
    source = tmp_path / "source.txt"
    source.write_bytes(b"source")

    with pytest.raises(CryptoFileError, match="Destination directory does not exist."):
        encrypt_file(source, PASSWORD, tmp_path / "missing", CONFIG)


def test_decrypt_file_rejects_missing_destination_directory(tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"source")
    encrypted_path = encrypt_file(source, PASSWORD, config=CONFIG)

    with pytest.raises(CryptoFileError, match="Destination directory does not exist."):
        decrypt_file_to_path(encrypted_path, PASSWORD, tmp_path / "missing", CONFIG)


def test_decrypt_file_rejects_non_directory_destination(tmp_path):
    source = tmp_path / "document.txt"
    source.write_bytes(b"source")
    encrypted_path = encrypt_file(source, PASSWORD, config=CONFIG)
    destination = tmp_path / "not-a-directory"
    destination.write_text("file")

    with pytest.raises(ValidationError, match="Destination path must be a directory."):
        decrypt_file_to_path(encrypted_path, PASSWORD, destination, CONFIG)


@pytest.mark.parametrize(
    ("source_path", "destination", "password", "config", "message"),
    [
        (123, None, PASSWORD, CONFIG, "Invalid source file path."),
        ("{source}", 123, PASSWORD, CONFIG, "Invalid destination path."),
        ("{source}", None, 123, CONFIG, "Invalid password."),
        ("{source}", None, PASSWORD, object(), "Invalid configuration object."),
    ],
)
def test_encrypt_file_rejects_invalid_argument_types(
    tmp_path, source_path, destination, password, config, message
):
    source = tmp_path / "source.txt"
    source.write_bytes(b"source")
    if source_path == "{source}":
        source_path = source

    with pytest.raises(ValidationError, match=message):
        encrypt_file(source_path, password, destination, config)