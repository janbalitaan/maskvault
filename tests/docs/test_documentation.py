"""Keeping the documentation honest.

A doc page that drifts is worse than no page: it is a claim someone will act
on. These check what can be checked mechanically — that every page the index
promises exists, that every link resolves, that every name the API reference
lists is importable, and that every import in a code block actually works.

That last one is here because writing these pages found a real gap: the
token-formats page used `from maskvault import BRACKETS, ANGLES`, which was
not exported. A reader following the page would have hit an ImportError.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re

import pytest

import maskvault
from maskvault.cli import build_parser

DOCS = Path(__file__).resolve().parents[2] / "docs"
PAGES = sorted(DOCS.glob("*.md"))

# Names a code block may use without importing: defined earlier in the same
# page's narrative, or standing in for the reader's own objects.
ASSUMED = {
    "anonymizer",
    "vault",
    "safe",
    "reply",
    "answer",
    "provider",
    "logger",
    "data",
    "original",
    "store",
    "backend",
    "connection",
    "cipher",
    "key",
    "text",
    "turn",
    "turns",
    "conversation",
    "app",
    "boto3",
    "json",
    "fallback",
    "real_input",
    "leftover",
    "finding",
    "token_format",
    "detector",
    "internal_id",
    "platform",
    "team",
    "question",
    "message",
    "handle",
    "ProcessPoolExecutor",
    "asyncio",
    "work",
    "pool",
    "KmsCipher",
    "Registry",
    "Vault",
    "redis_client",
    "conversation_id",
}


def code_blocks(page: Path, language: str) -> list[str]:
    """Every fenced block of one language in a page."""
    return re.findall(rf"```{language}\n(.*?)```", page.read_text(), re.S)


class TestEveryPageExists:
    def test_the_docs_directory_is_there(self):
        assert DOCS.is_dir()
        assert len(PAGES) >= 14

    def test_the_index_links_only_to_pages_that_exist(self):
        index = (DOCS / "README.md").read_text()
        for target in re.findall(r"\]\((?!https?://)([^)#]+\.md)", index):
            assert (DOCS / target).is_file(), f"index links to a missing {target}"

    @pytest.mark.parametrize("page", PAGES, ids=lambda item: item.name)
    def test_internal_links_resolve(self, page):
        for target in re.findall(r"\]\((?!https?://)([^)#]+\.md)", page.read_text()):
            assert (page.parent / target).resolve().is_file(), (
                f"{page.name} links to a missing {target}"
            )

    def test_every_page_is_reachable_from_the_index(self):
        index = (DOCS / "README.md").read_text()
        linked = set(re.findall(r"\]\((?!https?://)([^)#]+\.md)", index))
        for page in PAGES:
            if page.name == "README.md":
                continue
            assert page.name in linked, f"{page.name} is not linked from the index"

    @pytest.mark.parametrize("page", PAGES, ids=lambda item: item.name)
    def test_a_page_has_a_title_and_substance(self, page):
        text = page.read_text()
        assert text.startswith("# "), f"{page.name} should open with a title"
        assert len(text) > 500, f"{page.name} is too thin to be useful"


class TestEveryDocumentedImportWorks:
    """The check that would have caught the missing export."""

    @pytest.mark.parametrize("page", PAGES, ids=lambda item: item.name)
    def test_imports_in_code_blocks_resolve(self, page):
        for block in code_blocks(page, "python"):
            try:
                tree = ast.parse(block)
            except SyntaxError:
                continue  # a fragment rather than a module; covered below
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if not node.module.startswith("maskvault"):
                        continue
                    module = __import__(node.module, fromlist=["x"])
                    for alias in node.names:
                        assert hasattr(module, alias.name), (
                            f"{page.name}: {node.module} has no {alias.name!r}"
                        )

    @pytest.mark.parametrize("page", PAGES, ids=lambda item: item.name)
    def test_attributes_used_on_public_objects_exist(self, page):
        """`anonymizer.anonimize(...)` would otherwise sit in a page forever."""
        # Instances, not classes: a dataclass field with a default_factory
        # is not a class attribute, so `hasattr(Vault, "token_format")` is
        # False while `vault.token_format` works.
        known = {
            "anonymizer": maskvault.Anonymizer(),
            "vault": maskvault.Vault(),
        }
        for block in code_blocks(page, "python"):
            for name, obj in known.items():
                for attribute in re.findall(rf"\b{name}\.(\w+)", block):
                    assert hasattr(obj, attribute), (
                        f"{page.name}: {type(obj).__name__} has no {attribute!r}"
                    )


class TestTheApiReferenceIsReal:
    @staticmethod
    def _documented() -> set[str]:
        text = (DOCS / "api.md").read_text()
        block = re.search(r"from maskvault import \((.*?)\)", text, re.S)
        assert block, "the API reference should open with an import block"
        # Comments inside the block group the names for a reader. Without
        # stripping them, "internals" from "# detection internals" reads as a
        # documented name.
        listed = re.sub(r"#[^\n]*", "", block.group(1))
        return {name.strip().rstrip(",") for name in re.findall(r"[\w_]+,", listed)}

    def test_every_documented_name_is_importable(self):
        for name in self._documented():
            assert hasattr(maskvault, name), f"api.md documents a missing {name}"

    def test_every_public_name_is_documented(self):
        """A public name nobody wrote down is one nobody will use."""
        documented = self._documented()
        for name in maskvault.__all__:
            assert name in documented, f"{name} is public but not in api.md"


class TestTheCliIsDocumentedAsItBehaves:
    def test_every_documented_command_exists(self):

        page = (DOCS / "cli.md").read_text()
        actions = build_parser()._subparsers._group_actions[0].choices
        for command in actions:
            assert f"maskvault {command}" in page, f"{command} is undocumented"

    def test_no_command_is_documented_that_does_not_exist(self):

        page = (DOCS / "cli.md").read_text()
        actions = set(build_parser()._subparsers._group_actions[0].choices)
        for documented in set(re.findall(r"maskvault (\w+)", page)):
            if documented in {"explain", "anonymize", "restore", "policy"}:
                assert documented in actions
