"""Exception hierarchy.

Every failure the vault can report derives from :class:`VaultError`, so callers
can catch one type. The subclasses matter because they mean different things to
the user: a wrong password is routine, an integrity failure means the file was
modified and they should restore a backup.
"""

from __future__ import annotations


class VaultError(Exception):
    """Base class for every error raised by SecureVault."""


class VaultFormatError(VaultError):
    """The file is not a well-formed vault: bad magic, truncated, malformed header."""


class UnsupportedVersionError(VaultFormatError):
    """The vault was written by a newer, incompatible version of the format."""


class WeakKdfError(VaultFormatError):
    """The header requests KDF parameters below the security floor.

    A genuine vault never does this, so it suggests the file was swapped for one
    built to make the master password cheap to crack. We refuse before running
    the KDF so the password is never processed with those parameters.
    """


class AuthenticationError(VaultError):
    """Wrong master password or keyfile.

    A corrupted key slot looks identical to a wrong password. That is inherent
    to authenticated encryption and not something to paper over.
    """


class IntegrityError(VaultError):
    """The key was correct but the header or payload failed authentication.

    This only happens if the file was modified or damaged after it was written.
    """


class VaultConflictError(VaultError):
    """The vault file changed on disk after it was opened (another process saved)."""


class VaultExistsError(VaultError):
    """Refusing to overwrite an existing vault."""


class EntryNotFoundError(VaultError):
    """No entry matches the query."""


class AmbiguousEntryError(VaultError):
    """More than one entry matches the query."""


class DuplicateEntryError(VaultError):
    """An entry with this title already exists."""
