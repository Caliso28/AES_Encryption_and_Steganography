# AES Encryption and Steganography

Password-based authenticated encryption for byte strings, binary streams, and
files, implemented with Argon2id and AES-GCM.

> [!NOTE]
> Despite the repository name, this project does not currently implement
> steganography. It provides encryption only.

## Features

- Derives encryption keys from passwords with Argon2id.
- Encrypts and authenticates data with AES-GCM.
- Provides separate APIs for in-memory bytes, chunked streams, and files.
- Authenticates stream records and detects tampering and truncation.
- Stages file output and publishes it only after the operation succeeds,
  without overwriting existing files.

## Installation

Clone the repository, then install the package and development dependencies
into your active Python environment:

```console
python scripts/manage_project.py install
```

This installs the project in editable mode, along with its test and
documentation tools. To install only the runtime package:

```console
python -m pip install .
```

The core runtime dependency is `cryptography` (version 44 or newer).

## Quick start

### Encrypt and decrypt a file

```python
from crypto.file_cipher import decrypt_file, encrypt_file

encrypted_path = encrypt_file("report.pdf", "a strong passphrase")
decrypted_path = decrypt_file(encrypted_path, "a strong passphrase")

print(f"Encrypted file: {encrypted_path}")
print(f"Decrypted file: {decrypted_path}")
```

Files are written beside the source by default. The optional `dest_path`
argument is an existing **directory**, not an output filename. Existing files
are preserved; a numbered name is chosen if the expected output name already
exists.

To configure a default output directory for both file encryption and
decryption, change the `files` setting in `src/config.py`. Its default is
`Files()`, whose `dest_path` is `None`, so files are written beside their
source. Set its `dest_path` field to an existing directory:

```python
files.dest_path = Path.home() / "Encrypted"
```

The `Files` settings are mutable, so this changes the existing `files` object;
you do not need to create a replacement. Since `Path` is already imported in
`config.py`, no additional import is needed there.

The configured directory must already exist. An explicit `dest_path` passed to
`encrypt_file` or `decrypt_file` takes precedence for that call.

### Encrypt an in-memory payload

```python
from crypto.aes_cipher import AESCipher
from crypto.encryption_orchestrator import EncryptionOrchestrator
from crypto.key_derivator import KeyDerivator

crypto = EncryptionOrchestrator(KeyDerivator(), AESCipher())
encrypted = crypto.encrypt("a strong passphrase", b"small payload")
plaintext = crypto.decrypt("a strong passphrase", encrypted)
```

The encrypted result is a dictionary containing Base64-encoded `salt`,
`nonce`, and `ciphertext` values. This in-memory representation is distinct
from the versioned format used by the stream and file APIs.

### Process a binary stream

```python
import io

from crypto.stream_crypto import decrypt_stream, encrypt_stream

encrypted = b"".join(
    encrypt_stream(io.BytesIO(b"payload"), "a strong passphrase")
)
plaintext = b"".join(
    decrypt_stream(io.BytesIO(encrypted), "a strong passphrase")
)
```

For large inputs, write each yielded chunk to a destination instead of joining
the chunks in memory. The caller owns the input streams. Consume the entire
decryption iterator so that final authentication and truncation checks run.

## Security notes

- Use a strong, unique passphrase and keep it secret. This package does not
  store or manage passwords or encryption keys.
- A fresh random salt and nonce material are generated for each encryption.
- The stream and file format authenticates each record. Do not treat a
  decryption as successful until the full stream has been consumed.
- This library does not provide steganography, key management, or a command-line
  encryption interface.

## Development

Run the correctness tests from the repository root:

```console
pytest tests/test_crypto
```

Performance benchmarks are opt-in:

```console
pytest -o addopts= -m benchmark tests/benchmarks
```

Build or preview the documentation locally:

```console
playwright install chromium
mkdocs build --strict
mkdocs serve
```

The build produces per-page PDF download buttons and a combined
`site/documentation.pdf`. A MkDocs post-build hook creates
`site/offline-docs.zip` automatically for both `mkdocs build` and `mkdocs
serve`; it contains the generated HTML, CSS, JavaScript, and PDF files.

## Documentation website

The documentation is published to
[GitHub Pages](https://caliso28.github.io/Chiffrement_AES_Et_Steganographie/)
whenever changes are pushed to `main`. To enable it in the repository, open
**Settings → Pages** and set the build and deployment source to **GitHub
Actions**. The workflow builds the MkDocs site, packages the offline ZIP, and
deploys both to Pages.

The project documentation covers [encryption workflows](docs/workflows.md),
the [encrypted stream format](docs/format.md), [benchmarks](docs/benchmarks.md),
and the [API reference](docs/api.md).

## License

This project is distributed under the MIT License. See [LICENCE](LICENCE).
