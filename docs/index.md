# AES Encryption and Steganography

This project provides password-based authenticated encryption for in-memory
byte strings, binary streams, and files. It uses Argon2id to derive keys and
AES-GCM to encrypt and authenticate data. The file and stream interface
processes input in chunks instead of loading the entire input into memory.

<p>
  <a href="documentation.pdf">Download the complete documentation as a PDF</a>
  or <a href="offline-docs.zip">download the offline site as a ZIP</a>.
  The ZIP keeps the generated HTML, CSS, and JavaScript together; extract it
  and open <code>index.html</code> to browse the documentation.
</p>

If your browser blocks search while opening the file directly, start a local
server from the extracted directory with `python -m http.server 8000`, then
visit `http://localhost:8000`.

!!! warning "Security scope"
    This repository implements encryption primitives and file handling. It does
    not implement steganography, password storage, or a key-management system.
    Keep passwords secret, use a fresh salt for every encryption, and never
    reuse an AES-GCM nonce with the same key.

## Quick start

From the repository root, install the project and its development/documentation
tools into the active Python environment:

```console
python scripts/manage_project.py install
```

To uninstall the project:

```console
python scripts/manage_project.py uninstall
```

Uninstalling removes the project package only; shared dependencies are left in
place. MkDocs displays these commands but does not execute them. Run them in a
terminal from a local checkout.

Encrypt and then decrypt a file. The destination argument is a **directory**;
when omitted, outputs are placed beside the source file.

```python
from crypto.file_cipher import decrypt_file, encrypt_file

encrypted_path = encrypt_file("report.pdf", "a strong passphrase")
decrypted_path = decrypt_file(encrypted_path, "a strong passphrase")
```

Build and serve the documentation locally:

```console
mkdocs serve
mkdocs build --strict
```

Run the crypto correctness suite with `pytest tests/test_crypto`. Performance
tests are opt-in; see [Benchmarks](benchmarks.md).

## Start here

- Learn which API to use in [Encryption workflows](workflows.md).
- Read about headers and authenticated records in [Encrypted stream format](format.md).
- Browse all documented modules and callables in the [API reference](api.md).
