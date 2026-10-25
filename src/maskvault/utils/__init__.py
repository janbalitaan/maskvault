"""Helpers that know nothing about anonymization.

The test for belonging here is whether a function would make sense in an
unrelated project. `shannon_entropy` would — it measures a string. Deciding
whether a string is a *secret* would not, so that stays in `entropy.py` where
the domain lives.

Grouped as classes rather than left as loose functions, so each file is one
named thing a reader can look up. The methods are static: these are
calculations, not objects with state, and making the caller construct
something to reach a pure function buys nothing.
"""

from maskvault.utils.text import TextMetrics

__all__ = ["TextMetrics"]
