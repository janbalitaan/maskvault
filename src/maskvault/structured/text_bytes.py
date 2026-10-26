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

from collections.abc import Callable

# A BOM is a declaration, so it is honoured over the configured encoding.
# Ordered longest first: the UTF-32 marks begin with the UTF-16 ones, so a
# shorter prefix would match a UTF-32 payload and decode it as UTF-16.
_BYTE_ORDER_MARKS: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xff\xfe", "utf-16-le"),
)


class BytesText:
    """Decodes bytes to text and back, or declines to."""

    @staticmethod
    def encoding_for(data: bytes, configured: str | None) -> str | None:
        """Return the encoding to use, honouring a byte-order mark.

        None means do not treat these bytes as text at all.
        """
        if configured is None:
            return None
        for mark, encoding in _BYTE_ORDER_MARKS:
            if data.startswith(mark):
                return encoding
        return configured

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
        * re-encoding the *unmodified* text does not reproduce the original
          bytes, which means the codec lost information and writing it back
          would corrupt the payload;
        * nothing matched, so there is no reason to re-encode at all.

        That last case matters most. Most byte strings in a payload contain
        nothing sensitive, and returning them by identity means the common
        path cannot corrupt anything even if a codec misbehaves.
        """
        chosen = BytesText.encoding_for(bytes(data), encoding)
        if chosen is None:
            return data
        try:
            text = bytes(data).decode(chosen)
        except (UnicodeDecodeError, LookupError):
            return data
        if not BytesText._is_lossless(text, chosen, bytes(data)):
            return data

        replaced = replace(text)
        if replaced == text:
            return data
        try:
            encoded = replaced.encode(chosen)
        except UnicodeEncodeError:
            # A restored value may hold characters this codec cannot write.
            # Returning the tokenized bytes keeps them resolvable rather than
            # raising mid-payload; `leaked()` reports what did not come back.
            return data
        return bytearray(encoded) if isinstance(data, bytearray) else encoded

    @staticmethod
    def _is_lossless(text: str, encoding: str, original: bytes) -> bool:
        """Whether encoding the text back reproduces the original bytes.

        Some codecs decode without complaint and encode to something else —
        `utf-8-sig` strips the mark it read, and a few legacy codecs map
        several byte values onto one character. Writing that back would
        silently alter a payload nothing was wrong with, so the check runs
        before anything is replaced rather than after.
        """
        try:
            return text.encode(encoding) == original
        except UnicodeEncodeError:
            return False
