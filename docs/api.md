# API reference

The reference below is generated from the Python source docstrings using
mkdocstrings. Private implementation helpers are included where they are part
of the documented internal behavior.

## Configuration

::: config
    options:
      members:
        - Crypto
        - Steganography
        - Files
        - files

## Exceptions

::: crypto.exceptions
    options:
      members:
        - CryptoError
        - ValidationError
        - CryptoFileError
        - HeaderError
        - UnsupportedVersionError
        - IntegrityError
        - TruncatedStreamError

## Key derivation

::: crypto.key_derivator
    options:
      members:
        - KeyDerivator

## AES-GCM

::: crypto.aes_cipher
    options:
      members:
        - AESCipher

## In-memory encryption

::: crypto.encryption_orchestrator
    options:
      members:
        - EncryptionOrchestrator

## Stream encryption

::: crypto.stream_crypto
    options:
      members:
        - _read_up_to
        - encrypt_stream
        - decrypt_stream

## File encryption

::: crypto.file_cipher
    options:
      members:
        - _get_path_lock
        - _output_path
        - _decrypted_output_path
        - encrypt_file
        - decrypt_file
