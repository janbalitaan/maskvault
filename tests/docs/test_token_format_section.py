"""TestTokenFormatSection."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level, TokenFormat


class TestTokenFormatSection:
    def test_the_wikilink_example(self):
        """README: 'see [[Notes]], I work at !|ORG_1|!' and name 'pipe_bang'."""
        anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})
        safe, vault = anonymizer.anonymize("see [[Notes]], I work at Acme Corp")
        assert safe == "see [[Notes]], I work at !|ORG_1|!"
        assert vault.token_format.name == "pipe_bang"

    def test_pinning_by_name_works(self):
        """README: Anonymizer(token_format="pipe_bang")."""
        anonymizer = Anonymizer(token_format="pipe_bang", terms={"ORG": ["Acme"]})
        assert "!|ORG_1|!" in anonymizer.anonymize("I work at Acme")[0]

    def test_the_lowercase_custom_format_example(self):
        """README shows this exact format producing <%|org_1|%>."""
        anonymizer = Anonymizer(
            token_format=TokenFormat(
                name="mine",
                opening="<%|",
                closing="|%>",
                label_pattern=r"[a-z_]+",
                label_case="lower",
            ),
            terms={"ORG": ["Acme"]},
        )
        assert "<%|org_1|%>" in anonymizer.anonymize("I work at Acme")[0]

    def test_the_documented_validation_error(self):
        """README shows the ValueError text for a mismatched format."""
        with pytest.raises(ValueError, match=r"cannot match its own output"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_pattern=r"\d+")
