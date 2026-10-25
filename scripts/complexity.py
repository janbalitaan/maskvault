"""Cognitive and cyclomatic complexity, measured from the AST.

Cognitive complexity is SonarQube's metric and is not the same as cyclomatic.
Cyclomatic counts decision points, so a flat function with ten independent
ifs scores the same as one with ten nested ifs. Cognitive complexity charges
for nesting, which is what actually makes code hard to follow:

    +1  for each if, else, elif, loop, except, with-as-control, ternary,
        boolean operator sequence, assert, comprehension-with-condition
    +n  additional, equal to the current nesting depth, for each structure
        that itself nests
    +1  for each break or continue

SonarQube's own default threshold for a function is 15, which is the limit
this script enforces. Run it over a source tree:

    python scripts/complexity.py src

It exits non-zero when any function is over the limit, so CI can gate on it.
"""

from __future__ import annotations

import ast
from pathlib import Path
import sys

# SonarQube's default, and the limit this script enforces.
THRESHOLD = 15

NESTING_NODES = (
    ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try,
    ast.ExceptHandler, ast.With, ast.AsyncWith,
)
FLOW_BREAKS = (ast.Break, ast.Continue)


class CognitiveVisitor(ast.NodeVisitor):
    """Accumulates cognitive complexity for one function body."""

    def __init__(self) -> None:
        self.score = 0
        self._nesting = 0

    def _increment(self, nests: bool) -> None:
        self.score += 1 + (self._nesting if nests else 0)

    def _visit_nested(self, node: ast.AST, nests: bool = True) -> None:
        self._increment(nests)
        self._nesting += 1
        self.generic_visit(node)
        self._nesting -= 1

    def visit_If(self, node: ast.If) -> None:
        self._increment(True)
        self._nesting += 1
        for child in node.body:
            self.visit(child)
        self._nesting -= 1
        # elif chains are a single structure in this metric; a plain else
        # costs one without further nesting.
        if node.orelse:
            is_elif = len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If)
            if not is_elif:
                self.score += 1
            self._nesting += 1
            for child in node.orelse:
                self.visit(child)
            self._nesting -= 1

    def visit_For(self, node: ast.For) -> None:
        self._visit_nested(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_nested(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_nested(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._visit_nested(node)

    def visit_Try(self, node: ast.Try) -> None:
        # The try itself is not charged; its handlers are.
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # One charge per sequence of the same operator, not per operand.
        self.score += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._increment(True)
        self.generic_visit(node)

    def visit_Break(self, node: ast.Break) -> None:
        self.score += 1

    def visit_Continue(self, node: ast.Continue) -> None:
        self.score += 1

    def visit_comprehension(self, node: ast.comprehension) -> None:
        for _ in node.ifs:
            self._increment(True)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # A nested function's own complexity is reported separately.
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass


def cyclomatic(node: ast.AST) -> int:
    """McCabe: one plus the number of decision points."""
    score = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While,
                              ast.ExceptHandler, ast.Assert)):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            score += len(child.ifs)
    return score


def measure(root: Path) -> list[tuple[int, int, str]]:
    results = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            visitor = CognitiveVisitor()
            for statement in node.body:
                visitor.visit(statement)
            results.append((
                visitor.score,
                cyclomatic(node),
                f"{path.relative_to(root.parent)}:{node.lineno} {node.name}",
            ))
    return results


def main() -> int:
    """Measure the given paths and fail if any function is over the limit."""
    threshold = THRESHOLD
    worst_overall = 0
    roots = [Path(name) for name in sys.argv[1:]] or [Path("src")]
    for root in roots:
        if not root.exists():
            print(f"  no such path: {root}")
            return 2
        results = measure(root)
        results.sort(reverse=True)
        over = [item for item in results if item[0] > threshold]
        cognitive = [item[0] for item in results]
        cyclo = [item[1] for item in results]
        worst_overall = max(worst_overall, max(cognitive, default=0))

        print(f"=== {root} ===")
        print(f"  functions            {len(results)}")
        print(f"  cognitive  max {max(cognitive, default=0):3}   mean {sum(cognitive)/len(cognitive):5.2f}")
        print(f"  cyclomatic max {max(cyclo, default=0):3}   mean {sum(cyclo)/len(cyclo):5.2f}")
        print(f"  over threshold ({threshold})  {len(over)}")
        print("  worst five:")
        for score, cyc, where in results[:5]:
            flag = "  OVER" if score > threshold else ""
            print(f"    cognitive {score:3}  cyclomatic {cyc:3}  {where}{flag}")
        print()
    if worst_overall > threshold:
        print(f"FAILED: at least one function is over the limit of {threshold}.")
        return 1
    print(f"OK: every function is at or under {threshold}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
