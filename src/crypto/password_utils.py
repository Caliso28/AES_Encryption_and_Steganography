"""Shared password preparation for versioned encryption formats."""

import unicodedata

from .exceptions import ValidationError


def prepare_password(password: str) -> bytes:
    """Normalize a string password to Unicode NFC and encode it as UTF-8.

    Empty-password policy is enforced by the public encryption APIs.

    Raises:
        ValidationError: If ``password`` is not a string or cannot be encoded
            as UTF-8.
    """
    if not isinstance(password, str):
        raise ValidationError("The password must be of type 'str'.")
    try:
        return unicodedata.normalize("NFC", password).encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValidationError("The password cannot be encoded in UTF-8.") from error

