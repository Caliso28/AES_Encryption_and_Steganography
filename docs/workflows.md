# Encryption workflows

## In-memory payloads

Use `EncryptionOrchestrator` when the full plaintext is already a `bytes`
object. Its result is a dictionary of Base64 strings that can be serialized by
an application, with a format version, AES-GCM identifier, Argon2id parameters,
and password encoding/normalization identifiers. It generates a random salt
and nonce and derives an AES key with the recorded Argon2id parameters.

```python
from crypto.aes_cipher import AESCipher
from crypto.encryption_orchestrator import EncryptionOrchestrator
from crypto.key_derivator import KeyDerivator

crypto = EncryptionOrchestrator(KeyDerivator(), AESCipher())
record = crypto.encrypt("passphrase", b"small payload")
plaintext = crypto.decrypt("passphrase", record)
```

This representation is not the on-disk stream format: use the streaming APIs
for large inputs and files.

New in-memory records normalize passwords to Unicode NFC before UTF-8 encoding.
The metadata is authenticated as AES-GCM associated data. Decryption accepts
the versioned mapping format only.

`KeyDerivator()` uses the production security profile by default. If a
test needs faster derivation, pass `profile=KDFProfile.TEST` explicitly; do
not use that profile for production data. Decryption normally enforces the
production minimums; to decrypt test files made with weaker parameters, use
the test profile explicitly. For stream tests, set `Crypto.KDF_PROFILE` to
`KDFProfile.TEST` as well.

Production derivations are capped at 256 MiB and 5 Argon2id iterations.
Derivations are serialized within each process, and a call that cannot get a
slot within one second fails with `KDFBusyError`. The iteration cap limits
computational work, but it is not a hard wall-clock timeout because the native
Argon2id operation cannot safely be interrupted in-process.

## Streaming data

`encrypt_stream` and `decrypt_stream` accept readable binary streams and return
iterators of byte chunks. The caller owns and closes the streams. Always
consume the full decryption iterator: authentication and truncation checks are
performed record by record, and an incomplete final stream is only detected
when the iterator reaches its end.

```python
import io

from crypto.stream_crypto import decrypt_stream, encrypt_stream

encrypted = b"".join(encrypt_stream(io.BytesIO(b"payload"), "passphrase"))
plaintext = b"".join(decrypt_stream(io.BytesIO(encrypted), "passphrase"))
```

For large streams, write each yielded chunk to a destination rather than
joining all chunks in memory.

## Files

`encrypt_file` and `decrypt_file` are wrappers around the streaming API. They:

- accept a source path and an optional existing destination **directory**;
- use `files.dest_path` from `config.py` when no destination argument is
  provided, falling back to the source directory when that setting is `None`;
- choose a numbered output filename rather than overwrite an existing file;
- stage results in a temporary file in the destination directory;
- synchronize the completed temporary file before publication;
- publish with atomic no-replace semantics, so concurrent processes use
  different numbered names rather than overwrite one another.

Publication uses a hard link within the destination filesystem. That
filesystem must support hard links; if it does not, the operation fails rather
than falling back to an overwrite-prone rename. Synchronizing the file contents
does not guarantee that the directory entry survives a sudden power loss.

Set the project-wide default by changing the existing mutable settings object
in `config.py`, for example `files.dest_path = Path("output")`. An explicit
`dest_path` argument overrides that setting for one call. Any selected
destination must identify an existing directory.

If decryption fails, no partially decrypted destination is published. File
names use `_encrypted` and `_decrypted` suffixes.

## Data flow

```mermaid
flowchart LR
    Password --> Argon2id
    Salt --> Argon2id
    Argon2id --> AESKey["AES-256 key"]
    Plaintext --> Chunker
    NonceBase["Random nonce base"] --> NonceCounter["Nonce base + record counter"]
    Chunker --> AESGCM
    AESKey --> AESGCM
    NonceCounter --> AESGCM
    RecordMetadata["Counter, final-record flag, plaintext length"] --> AESGCM
    AESGCM --> AuthenticatedRecords["Ciphertext + authentication tag"]
    Header["Versioned header: salt, KDF parameters, chunk size, nonce base"] --> Output
    AuthenticatedRecords --> Output
```

## Error handling

Catch the package's `CryptoError` base class when an application wants to handle
expected crypto failures uniformly. More specific subclasses distinguish
invalid input (`ValidationError`), malformed headers (`HeaderError`), failed
authentication (`IntegrityError`), unsupported format versions
(`UnsupportedVersionError`), incomplete streams (`TruncatedStreamError`), and
resource contention (`KDFBusyError`). File and stream I/O failures use
`CryptoFileError`.
