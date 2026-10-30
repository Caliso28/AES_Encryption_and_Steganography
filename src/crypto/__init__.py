"""Authenticated encryption utilities for bytes, streams, and files.

The :mod:`crypto` package exposes its implementation through focused modules:
:mod:`crypto.aes_cipher`, :mod:`crypto.encryption_orchestrator`,
:mod:`crypto.stream_crypto`, and :mod:`crypto.file_cipher`.
"""

from crypto import encryption_orchestrator
from crypto import file_cipher