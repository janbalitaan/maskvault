"""TestQuickStart."""

from __future__ import annotations

from maskvault import Anonymizer, Level


class TestQuickStart:
    def test_the_opening_example(self):
        """README: 'I work at !|ORG_1|!, email !|EMAIL_1|!'.

        At-signs rather than brackets because no common markup claims
        them, and the output may be rendered somewhere this library
        cannot see.
        """
        anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})
        safe, vault = anonymizer.anonymize("I work at Acme Corp, email me@acme.com")
        assert safe == "I work at !|ORG_1|!, email !|EMAIL_1|!"
        assert anonymizer.restore(safe, vault) == "I work at Acme Corp, email me@acme.com"
