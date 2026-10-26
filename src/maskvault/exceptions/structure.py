"""Raised when a structure cannot be walked safely."""

from __future__ import annotations

from maskvault.exceptions.base import MaskvaultError


class StructureError(MaskvaultError):
    """A structure is too deep to walk, or refers to itself.

    Raised rather than worked around, because the alternative was worse than
    an error. The walker used to return a node unchanged once it passed the
    depth cap — so a structure eighty levels deep had the values below level
    sixty-four pass through in the clear, with an empty vault and a
    successful return. A cycle was worse still: the output held a reference
    to the *original* object, real values and all.

    A privacy filter that silently stops filtering is the one failure mode
    worth refusing outright. If a legitimate structure is this deep, raise
    the limit with `max_depth`; if it refers to itself, flatten it first.
    """
