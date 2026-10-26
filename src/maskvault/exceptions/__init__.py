"""Everything this library raises.

One file per class, as in `models/`, so a new exception is a new file rather
than an edit to a shared one. The tree, for deciding what to catch:

    MaskvaultError                  everything below
      TokenFormatError              a format cannot read back its own output
      DetectorError                 a pattern or capture group is wrong
      WhitelistError                an allowlist rule will not compile

Each leaf also inherits from the built-in it replaces — `ValueError` for all
each — so `except ValueError` keeps working for a caller who has not adopted
these. That is what the standard library does with
`UnicodeDecodeError(ValueError, UnicodeError)`, and it means introducing a
more specific type is never a breaking change.
"""

from maskvault.exceptions.base import MaskvaultError
from maskvault.exceptions.detector import DetectorError
from maskvault.exceptions.structure import StructureError
from maskvault.exceptions.token_format import TokenFormatError
from maskvault.exceptions.vault import VaultError
from maskvault.exceptions.whitelist import WhitelistError

__all__ = [
    "DetectorError",
    "MaskvaultError",
    "StructureError",
    "TokenFormatError",
    "VaultError",
    "WhitelistError",
]
