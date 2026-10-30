"""Exception hierarchy for input, encryption, stream, and integrity failures."""

class CryptoError(Exception):
    """Base class for all errors intentionally exposed by the crypto package."""
    pass

class ValidationError(CryptoError):
    """An argument or configuration value has an invalid type, size, or value."""
    pass

class CryptoFileError(CryptoError):
    """Base class for I/O and encrypted-stream format errors."""
    pass

class HeaderError(CryptoFileError):
    """An encrypted stream header is incomplete, malformed, or disallowed."""
    pass

class UnsupportedVersionError(HeaderError):
    """The encrypted stream uses an unknown magic value or format version."""
    pass

class IntegrityError(CryptoFileError):
    """Authentication failed because data was changed or the password is wrong."""
    pass

class TruncatedStreamError(CryptoFileError):
    """The encrypted stream ended before a complete final record was available."""
    pass
