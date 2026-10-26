"""Reading text out of bytes, and putting it back.

A byte string in a payload is usually text — a request body, a form field, a
file read in binary mode — and used to be skipped entirely, so its values
went out in the clear while the strings beside them were masked.

Deciding *which* text is the whole difficulty. UTF-8 is the right default
because it **refuses** what it cannot read: a PNG raises and is left alone.
latin-1 and cp1252 decode any byte sequence at all, so they cannot be tried
as a fallback — an image would decode successfully, be scanned as text, and
one chance match would corrupt it. So a caller whose payload is in one of
those declares it, and nothing is guessed.

A byte-order mark is the exception, because a BOM is not a guess: it is the
payload declaring its own encoding, and a caller who sent one has already
answered the question.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

# A BOM is a declaration, so it is honoured over the configured encoding.
# Ordered longest first: the UTF-32 marks begin with the UTF-16 ones, so a
# shorter prefix would match a UTF-32 payload and decode it as UTF-16.
#
# Each maps to a codec that reads the *body* after the mark, never one that
# handles the mark itself. The mark is carried separately and written back
# verbatim, which is what keeps the round trip exact — see `_split`.
_BYTE_ORDER_MARKS: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)

# Codecs that write a mark of their own. Asked for one of these, the mark is
# taken off the name and handled as data: `utf-8-sig` becomes "utf-8" plus a
# mark that is present or absent according to the payload.
#
# Letting the codec do it was the bug. `utf-8-sig` on bytes with no mark
# decodes cleanly and then *writes* a mark that was never there, so the round
# trip was not exact and the bytes were left unscanned — silently, and
# `utf-8-sig` is exactly what a caller declares for files that may or may not
# carry one.
_MARK_WRITING_CODECS: Mapping[str, str] = MappingProxyType(
    {
        "utf-8-sig": "utf-8",
        "utf_8_sig": "utf-8",
        "utf8-sig": "utf-8",
        # `utf-16` and `utf-32` write a mark too, and reading unmarked bytes
        # with them had the same effect: decode fine, re-encode with a mark
        # that was never there, round trip inexact, bytes skipped.
        #
        # Mapped to the little-endian variants, which is what Python's own
        # `utf-16` decoder assumes for unmarked input — so this makes an
        # existing assumption explicit rather than adding one. Marked input
        # never reaches here: `_split` matches the mark first and returns the
        # endianness it states.
        "utf-16": "utf-16-le",
        "utf_16": "utf-16-le",
        "utf16": "utf-16-le",
        "utf-32": "utf-32-le",
        "utf_32": "utf-32-le",
        "utf32": "utf-32-le",
    }
)


class BytesText:
    """Decodes bytes to text and back, or declines to."""

    @staticmethod
    def encoding_for(data: bytes, configured: str | None) -> str | None:
        """Return the codec that reads this payload's body.

        None means do not treat these bytes as text at all. A byte-order mark
        in the data wins over `configured`, because a mark is the payload
        stating its own encoding rather than a guess.
        """
        if configured is None:
            return None
        _, encoding = BytesText._split(data, configured)
        return encoding

    @staticmethod
    def _split(data: bytes, configured: str) -> tuple[bytes, str]:
        """Separate a leading byte-order mark from the body it introduces.

        Returns the mark's literal bytes and the codec for what follows. The
        mark is written back exactly as it arrived, so a payload that had one
        keeps it and a payload that had none does not acquire one.
        """
        for mark, encoding in _BYTE_ORDER_MARKS:
            if data.startswith(mark):
                return mark, encoding
        return b"", _MARK_WRITING_CODECS.get(configured.lower(), configured)

    @staticmethod
    def transform(
        data: bytes | bytearray,
        encoding: str | None,
        replace: Callable[[str], str],
    ) -> bytes | bytearray:
        """Decode, apply `replace`, and encode back — or return `data` as it is.

        Returns the original object untouched in every case where the round
        trip is not provably safe:

        * no encoding configured, so bytes are not text here;
        * the bytes do not decode, so they are binary;
        * re-encoding the *unmodified* body does not reproduce it, which
          means the codec lost information and writing it back would corrupt
          the payload. A byte-order mark is not such a loss: it is split off
          first and written back verbatim;
        * nothing matched, so there is no reason to re-encode at all.

        That last case matters most. Most byte strings in a payload contain
        nothing sensitive, and returning them by identity means the common
        path cannot corrupt anything even if a codec misbehaves.
        """
        if encoding is None:
            return data
        raw = bytes(data)
        mark, chosen = BytesText._split(raw, encoding)
        body = raw[len(mark) :]
        try:
            text = body.decode(chosen)
        except (UnicodeDecodeError, LookupError):
            return data
        if not BytesText._is_lossless(text, chosen, body):
            return data

        replaced = replace(text)
        if replaced == text:
            return data
        try:
            encoded = mark + replaced.encode(chosen)
        except UnicodeEncodeError:
            # A restored value may hold characters this codec cannot write.
            # Returning the tokenized bytes keeps them resolvable rather than
            # raising mid-payload; `leaked()` reports what did not come back.
            return data
        return bytearray(encoded) if isinstance(data, bytearray) else encoded

    @staticmethod
    def _is_lossless(text: str, encoding: str, original: bytes) -> bool:
        """Whether encoding the text back reproduces the original bytes.

        A byte-order mark no longer reaches this check — it is split off and
        carried separately. What remains are codecs that genuinely lose
        information: a few legacy ones map several byte values onto a single
        character, so writing the text back would alter a payload nothing was
        wrong with. The check runs before anything is replaced rather than
        after, so the decision is made while the original is still intact.
        """
        try:
            return text.encode(encoding) == original
        except UnicodeEncodeError:
            return False
