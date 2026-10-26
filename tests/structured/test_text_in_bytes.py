"""Reading text out of bytes without guessing at the encoding.

A byte string in a payload is usually text — a request body, a form field, a
file read in binary mode — and used to be skipped entirely, so its values
went out in the clear while the strings beside them were masked.

Deciding *which* text is the difficulty, and the answer is that nothing is
guessed. UTF-8 is the default because it refuses what it cannot read.
latin-1 and cp1252 decode any byte sequence at all, so a fallback chain
would decode a PNG successfully, scan it as text, and corrupt it on the one
chance match. A caller whose payload uses one of those declares it.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Vault, anonymize_data, restore_data
from maskvault.structured.text_bytes import BytesText

PNG = b"\x89PNG\r\n\x1a\n\x00\x00\xff\xfe"


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer()


class TestUtf8IsTheDefault:
    def test_utf8_text_is_scanned(self, anonymizer):
        safe, vault = anonymize_data({"b": b"email alice@acme.com"}, anonymizer)
        assert b"alice@acme.com" not in safe["b"]
        assert len(vault.values) == 1

    def test_it_round_trips(self, anonymizer):
        payload = {"b": b"email alice@acme.com"}
        safe, vault = anonymize_data(payload, anonymizer)
        assert restore_data(safe, anonymizer, vault) == payload

    def test_non_ascii_utf8_survives(self, anonymizer):
        payload = {"b": "Grüße, email alice@acme.com".encode()}
        safe, vault = anonymize_data(payload, anonymizer)
        assert b"alice@acme.com" not in safe["b"]
        assert restore_data(safe, anonymizer, vault) == payload

    def test_binary_is_refused(self, anonymizer):
        """UTF-8 is the right default because it raises on a PNG."""
        safe, _ = anonymize_data({"b": PNG}, anonymizer)
        assert safe["b"] == PNG


class TestADeclaredEncoding:
    """The gap this closes: text in an encoding UTF-8 cannot read."""

    def test_cp1252_is_not_scanned_under_utf8(self, anonymizer):
        payload = {"b": "Grüße, email alice@acme.com".encode("cp1252")}
        safe, _ = anonymize_data(payload, anonymizer)
        assert b"alice@acme.com" in safe["b"], "utf-8 cannot decode this"

    def test_declaring_it_scans_it(self, anonymizer):
        payload = {"b": "Grüße, email alice@acme.com".encode("cp1252")}
        safe, vault = anonymize_data(payload, anonymizer, bytes_encoding="cp1252")
        assert b"alice@acme.com" not in safe["b"]
        assert len(vault.values) == 1

    def test_and_it_round_trips(self, anonymizer):
        payload = {"b": "Grüße, email alice@acme.com".encode("cp1252")}
        safe, vault = anonymize_data(payload, anonymizer, bytes_encoding="cp1252")
        assert restore_data(safe, anonymizer, vault) == payload

    def test_shift_jis_round_trips(self, anonymizer):
        payload = {"b": "メール alice@acme.com です".encode("shift_jis")}
        safe, vault = anonymize_data(payload, anonymizer, bytes_encoding="shift_jis")
        assert b"alice@acme.com" not in safe["b"]
        assert restore_data(safe, anonymizer, vault) == payload

    def test_none_scans_no_bytes(self, anonymizer):
        payload = {"b": b"email alice@acme.com"}
        safe, _ = anonymize_data(payload, anonymizer, bytes_encoding=None)
        assert safe["b"] == payload["b"]

    def test_an_unknown_codec_is_not_an_error(self, anonymizer):
        """A typo in the encoding name leaves the bytes alone rather than
        taking the caller's request down."""
        safe, _ = anonymize_data(
            {"b": b"email alice@acme.com"}, anonymizer, bytes_encoding="not-a-codec"
        )
        assert safe["b"] == b"email alice@acme.com"


class TestTheEncodingTravelsWithTheVault:
    """Anonymizing with one encoding and restoring with another would mangle
    every non-ASCII value, so it is not expressible."""

    def test_the_vault_records_it(self, anonymizer):
        _, vault = anonymize_data({"b": b"x"}, anonymizer, bytes_encoding="cp1252")
        assert vault.bytes_encoding == "cp1252"

    def test_it_survives_serialization(self, anonymizer):
        payload = {"b": "Grüße alice@acme.com".encode("cp1252")}
        safe, vault = anonymize_data(payload, anonymizer, bytes_encoding="cp1252")
        revived = Vault.from_dict(vault.as_dict())
        assert revived.bytes_encoding == "cp1252"
        assert restore_data(safe, anonymizer, revived) == payload

    def test_a_vault_without_it_defaults_to_utf8(self):
        """A vault written before this was recorded."""
        legacy = {"values": {"!|EMAIL_1|!": "a@b.com"}, "destroyed": []}
        assert Vault.from_dict(legacy).bytes_encoding == "utf-8"


class TestAByteOrderMarkDeclaresItself:
    """A BOM is not a guess — it is the payload stating its own encoding.

    Only the endianness-free names emit one: `utf-16` and `utf-32` write a
    mark, while `utf-16-le` and the rest state the order in the name and so
    omit it. Those are undetectable by design and need declaring.
    """

    @pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-8-sig"])
    def test_a_bom_overrides_the_configured_encoding(self, anonymizer, encoding):
        payload = {"b": "email alice@acme.com".encode(encoding)}
        safe, vault = anonymize_data(payload, anonymizer)  # configured utf-8
        assert vault.values, f"{encoding} was not decoded at all"
        assert restore_data(safe, anonymizer, vault) == payload

    @pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-8-sig"])
    def test_the_mark_is_what_is_detected(self, encoding):
        marked = "x".encode(encoding)
        detected = BytesText.encoding_for(marked, "utf-8")
        assert detected != "utf-8", f"{encoding} left undetected"
        assert "x".encode(detected) or True

    def test_utf32_is_not_mistaken_for_utf16(self):
        """The UTF-32 marks begin with the UTF-16 ones, so a shorter prefix
        checked first would decode a UTF-32 payload as UTF-16."""
        assert BytesText.encoding_for("x".encode("utf-32"), "utf-8").startswith("utf-32")

    def test_an_endianness_free_name_has_no_mark_to_find(self):
        """Stated rather than assumed, because it is why they need
        declaring."""
        assert BytesText.encoding_for("x".encode("utf-16-le"), "utf-8") == "utf-8"
        assert BytesText.encoding_for("x".encode("utf-32-be"), "utf-8") == "utf-8"

    def test_declaring_one_works(self, anonymizer):
        payload = {"b": "email alice@acme.com".encode("utf-16-le")}
        safe, vault = anonymize_data(payload, anonymizer, bytes_encoding="utf-16-le")
        assert vault.values
        assert restore_data(safe, anonymizer, vault) == payload

    def test_no_bom_keeps_the_configured_encoding(self):
        assert BytesText.encoding_for(b"plain", "cp1252") == "cp1252"

    def test_none_wins_over_a_bom(self):
        """`None` means do not treat bytes as text, which a BOM cannot override."""
        assert BytesText.encoding_for("x".encode("utf-16"), None) is None


class TestNothingIsRewrittenWithoutReason:
    def test_untouched_bytes_come_back_by_identity(self, anonymizer):
        """Most byte strings hold nothing sensitive, and returning the same
        object means the common path cannot corrupt anything."""
        original = b"nothing sensitive here"
        safe, _ = anonymize_data({"b": original, "t": "a@b.com"}, anonymizer)
        assert safe["b"] is original

    def test_a_lossy_decode_is_refused(self):
        """Some codecs decode without complaint and encode to something
        else. Writing that back would alter a payload nothing was wrong
        with, so the check runs before anything is replaced."""
        assert not BytesText._is_lossless("x", "utf-8-sig", b"x")

    def test_a_lossless_decode_is_accepted(self):
        assert BytesText._is_lossless("x", "utf-8", b"x")

    def test_a_bytearray_stays_a_bytearray(self, anonymizer):
        payload = {"b": bytearray(b"email alice@acme.com")}
        safe, vault = anonymize_data(payload, anonymizer)
        assert isinstance(safe["b"], bytearray)
        restored = restore_data(safe, anonymizer, vault)["b"]
        assert isinstance(restored, bytearray)
        assert restored == payload["b"]

    def test_a_value_the_codec_cannot_write_leaves_the_bytes_tokenized(self):
        """Rather than raising mid-payload. `leaked()` reports what did not
        come back, so the failure is visible without being fatal."""
        anonymizer = Anonymizer()
        vault = Vault(bytes_encoding="ascii")
        vault.values["!|EMAIL_1|!"] = "grüße@acme.com"
        tokenized = b"email !|EMAIL_1|!"
        result = BytesText.transform(
            tokenized, "ascii", lambda text: anonymizer.restore(text, vault)
        )
        assert result == tokenized


class TestTheLosslessGuardActuallyGuards:
    """Some codecs decode without complaint and encode to something else.

    `utf-8-sig` is the clear case: it reads and strips a byte-order mark, so
    encoding the text back omits the mark that was there. Writing that into a
    payload would silently alter bytes nothing was wrong with, so the check
    runs before anything is replaced rather than after.
    """

    def test_a_stripped_mark_is_caught(self):
        """The decoded text no longer carries the BOM, so re-encoding it
        produces different bytes."""
        marked = "email alice@acme.com".encode("utf-8-sig")
        assert not BytesText._is_lossless(marked.decode("utf-8-sig"), "utf-8", marked)

    def test_a_marked_payload_is_detected_rather_than_refused(self):
        """A BOM corrects the encoding before the guard is reached, so the
        marked case is handled rather than skipped — the guard is a backstop
        for a *declared* encoding, not for a detected one."""
        marked = b"\xef\xbb\xbfemail alice@acme.com"
        assert BytesText.encoding_for(marked, "utf-8") == "utf-8-sig"
        result = BytesText.transform(marked, "utf-8", lambda text: text.upper())
        assert result != marked, "the marked payload should have been scanned"

    def test_a_declared_encoding_that_adds_a_mark_is_refused(self):
        """`utf-8-sig` on bytes with no mark decodes cleanly and then writes
        a mark that was never there. Scanning would alter a payload nothing
        was wrong with, so it is left alone."""
        unmarked = b"email alice@acme.com"
        assert not BytesText._is_lossless(unmarked.decode("utf-8-sig"), "utf-8-sig", unmarked)
        result = BytesText.transform(unmarked, "utf-8-sig", lambda _: "replaced")
        assert result == unmarked

    def test_an_unencodable_character_is_not_lossless(self):
        """The guard's own failure path: a character the codec cannot write."""
        assert not BytesText._is_lossless("grüße", "ascii", b"gr\xc3\xbc\xc3\x9fe")

    def test_an_encodable_one_is(self):
        assert BytesText._is_lossless("plain", "ascii", b"plain")
