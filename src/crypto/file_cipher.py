"""Atomic, collision-safe file encryption and decryption helpers."""

import os
import tempfile
import threading
from pathlib import Path
import config as project_config
from config import Crypto, Files
from .exceptions import CryptoFileError, ValidationError
from .stream_crypto import encrypt_stream, decrypt_stream


_path_locks: dict[str, threading.Lock] = {}
_path_locks_guard = threading.Lock()


def _get_path_lock(path: Path) -> threading.Lock:
    """Return a process-local lock keyed by a normalized absolute path."""
    lock_key = os.path.normcase(str(path.resolve()))
    with _path_locks_guard:
        return _path_locks.setdefault(lock_key, threading.Lock())


def _output_path(src_path: Path, dest_dir: Path, index: int) -> Path:
    """Build the next non-overwriting encrypted filename candidate."""
    numbered_stem = src_path.stem if index == 1 else f"{src_path.stem}_{index}"
    return dest_dir / f"{numbered_stem}_encrypted{src_path.suffix}"


def _decrypted_output_path(src_path: Path, dest_dir: Path, index: int) -> Path:
    """Build the next non-overwriting decrypted filename candidate."""
    encrypted_stem = src_path.stem
    for suffix in ("_encrypted", "_aes"):
        if encrypted_stem.endswith(suffix):
            encrypted_stem = encrypted_stem[: -len(suffix)]
            break
    decrypted_stem = f"{encrypted_stem}_decrypted"
    numbered_stem = decrypted_stem if index == 1 else f"{decrypted_stem}_{index}"
    return dest_dir / f"{numbered_stem}{src_path.suffix}"


def encrypt_file(
    src_path: str | Path,
    password: str | bytes,
    dest_path: str | Path | None = None,
    config: Crypto | None = Crypto(),
) -> Path:
    """Encrypt a file as a versioned authenticated stream.

    Output is written to a temporary file in the destination directory and
    renamed only after encryption succeeds. Existing outputs are preserved;
    numbered names are selected when necessary.

    Args:
        src_path: Existing source file.
        password: Password as UTF-8 text or raw bytes.
        dest_path: Existing destination directory; overrides
            ``files.dest_path`` from the project configuration. Despite its
            name, this argument is a directory.
        config: Stream format and KDF configuration, or ``None`` for defaults.

    Returns:
        The path of the newly created encrypted file.

    Raises:
        ValidationError: If a path, password, or configuration has an invalid
            type or value.
        CryptoFileError: If a path is missing or file I/O fails.
        CryptoError: If encryption or stream validation fails.
    """
    if not isinstance(src_path, (str, Path)):
        raise ValidationError("Invalid source file path.")
    src_file = Path(src_path)

    if not src_file.exists():
        raise CryptoFileError("Path does not exist on this volume.")
    if not src_file.is_file():
        raise ValidationError("The object isn't a file.")

    if config is not None and not isinstance(config, Crypto):
        raise ValidationError("Invalid configuration object.")
    effective_config = config if config is not None else Crypto()
    global_files = project_config.files
    if not isinstance(global_files, Files):
        raise ValidationError("Invalid files configuration object.")

    selected_dest_path = (
        dest_path if dest_path is not None else global_files.dest_path
    )
    if selected_dest_path is not None and not isinstance(
        selected_dest_path, (str, Path)
    ):
        raise ValidationError("Invalid destination path.")
    dest_dir = (
        src_file.parent
        if selected_dest_path is None
        else Path(selected_dest_path)
    )
    if not dest_dir.exists():
        raise CryptoFileError("Destination directory does not exist.")
    if not dest_dir.is_dir():
        raise ValidationError("Destination path must be a directory.")

    if not isinstance(password, (str, bytes)):
        raise ValidationError("Invalid password.")
    index = 1
    while True:
        final_path = _output_path(src_file, dest_dir, index)
        path_lock = _get_path_lock(final_path)
        with path_lock:
            if final_path.exists():
                index += 1
                continue

            temporary_path: Path | None = None
            try:
                # Keeping the temporary file beside the destination allows a
                # same-filesystem rename and avoids publishing partial output.
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=dest_dir,
                    prefix=f".{final_path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as temporary_file:
                    temporary_path = Path(temporary_file.name)
                    with src_file.open("rb") as source_stream:
                        for encrypted_chunk in encrypt_stream(
                            source_stream, password, effective_config
                        ):
                            temporary_file.write(encrypted_chunk)

                temporary_path.replace(final_path)
                temporary_path = None
                return final_path
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)


def decrypt_file(
    src_path: str | Path,
    password: str | bytes,
    dest_path: str | Path | None = None,
    config: Crypto | None = Crypto(),
) -> Path:
    """Authenticate and decrypt a versioned encrypted file.

    Output is staged in a temporary file and published only after the complete
    stream has been authenticated. Existing outputs are preserved; numbered
    names are selected when necessary.

    Args:
        src_path: Existing encrypted source file.
        password: Password as UTF-8 text or raw bytes.
        dest_path: Existing destination directory; overrides
            ``files.dest_path`` from the project configuration. Despite its
            name, this argument is a directory.
        config: Stream format and resource-limit configuration, or ``None``
            for defaults.

    Returns:
        The path of the newly created plaintext file.

    Raises:
        ValidationError: If a path, password, or configuration has an invalid
            type or value.
        CryptoFileError: If a path is missing, I/O fails, the header is invalid,
            or authentication fails.
    """
    if not isinstance(src_path, (str, Path)):
        raise ValidationError("Invalid source file path.")
    src_file = Path(src_path)

    if not src_file.exists():
        raise CryptoFileError("Path does not exist on this volume.")
    if not src_file.is_file():
        raise ValidationError("The object isn't a file.")
    if config is not None and not isinstance(config, Crypto):
        raise ValidationError("Invalid configuration object.")
    effective_config = config if config is not None else Crypto()
    global_files = project_config.files
    if not isinstance(global_files, Files):
        raise ValidationError("Invalid files configuration object.")

    selected_dest_path = (
        dest_path if dest_path is not None else global_files.dest_path
    )
    if selected_dest_path is not None and not isinstance(
        selected_dest_path, (str, Path)
    ):
        raise ValidationError("Invalid destination path.")
    dest_dir = (
        src_file.parent
        if selected_dest_path is None
        else Path(selected_dest_path)
    )
    if not dest_dir.exists():
        raise CryptoFileError("Destination directory does not exist.")
    if not dest_dir.is_dir():
        raise ValidationError("Destination path must be a directory.")

    if not isinstance(password, (str, bytes)):
        raise ValidationError("Invalid password.")
    index = 1
    while True:
        final_path = _decrypted_output_path(src_file, dest_dir, index)
        path_lock = _get_path_lock(final_path)
        with path_lock:
            if final_path.exists():
                index += 1
                continue

            temporary_path: Path | None = None
            try:
                # Do not expose plaintext until every record has authenticated;
                # a failed decryption must leave no partial destination behind.
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=dest_dir,
                    prefix=f".{final_path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as temporary_file:
                    temporary_path = Path(temporary_file.name)
                    with src_file.open("rb") as source_stream:
                        for decrypted_chunk in decrypt_stream(
                            source_stream, password, effective_config
                        ):
                            temporary_file.write(decrypted_chunk)

                temporary_path.replace(final_path)
                temporary_path = None
                return final_path
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
