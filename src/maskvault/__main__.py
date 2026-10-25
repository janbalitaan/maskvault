"""Lets the tool run as `python -m maskvault`, not only as `maskvault`.

Useful when the package is installed somewhere the console script is not on
PATH, which is common in a container.
"""

from __future__ import annotations

from maskvault.cli import run

run()
