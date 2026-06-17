#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly (no venv, no pip install needed):
#      uv run python -m scripts.build_rulesets --source Adguard-Home-For-Magisk-Mod --output dist
# 3. Or make executable and run:
#      chmod +x scripts/build_rulesets.py
#      PYTHONPATH=. ./scripts/build_rulesets.py --source Adguard-Home-For-Magisk-Mod --output dist
# ──────────────────

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scripts.ruleset_core import convert_repository, print_summary, write_outputs


@dataclass(frozen=True, slots=True)
class BuildArgs:
    source: Path
    output: Path
    upstream_commit: str


def parse_args(argv: Sequence[str]) -> BuildArgs:
    parser = argparse.ArgumentParser(description="Build mihomo rule-provider text sources.")
    _ = parser.add_argument("--source", type=Path, required=True)
    _ = parser.add_argument("--output", type=Path, required=True)
    _ = parser.add_argument("--upstream-commit", default="unknown")
    namespace = parser.parse_args(argv)
    parsed: dict[str, object] = vars(namespace)
    source = parsed["source"]
    output = parsed["output"]
    upstream_commit = parsed["upstream_commit"]
    if not isinstance(source, Path):
        raise TypeError
    if not isinstance(output, Path):
        raise TypeError
    if not isinstance(upstream_commit, str):
        raise TypeError
    return BuildArgs(
        source=source,
        output=output,
        upstream_commit=upstream_commit,
    )


def main() -> int:
    args = parse_args(sys.argv[1:])
    result = convert_repository(args.source, args.upstream_commit)
    write_outputs(result, args.output)
    print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
