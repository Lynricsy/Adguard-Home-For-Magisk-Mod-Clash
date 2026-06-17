#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from scripts.ruleset_core import convert_repositories, print_summary, write_outputs
from scripts.ruleset_types import UpstreamKind


@dataclass(frozen=True, slots=True)
class BuildArgs:
    adguard_source: Path
    anti_ad_source: Path
    coolapk_1007_reward_source: Path
    output: Path
    adguard_commit: str
    anti_ad_commit: str
    coolapk_1007_reward_commit: str


def parse_args(argv: Sequence[str]) -> BuildArgs:
    parser = argparse.ArgumentParser(description="Build mihomo rule-provider text sources.")
    _ = parser.add_argument("--adguard-source", type=Path, required=True)
    _ = parser.add_argument("--anti-ad-source", type=Path, required=True)
    _ = parser.add_argument("--coolapk-1007-reward-source", type=Path, required=True)
    _ = parser.add_argument("--output", type=Path, required=True)
    _ = parser.add_argument("--adguard-commit", default="unknown")
    _ = parser.add_argument("--anti-ad-commit", default="unknown")
    _ = parser.add_argument("--coolapk-1007-reward-commit", default="unknown")
    namespace = parser.parse_args(argv)
    parsed: dict[str, object] = vars(namespace)
    adguard_source = parsed["adguard_source"]
    anti_ad_source = parsed["anti_ad_source"]
    coolapk_1007_reward_source = parsed["coolapk_1007_reward_source"]
    output = parsed["output"]
    adguard_commit = parsed["adguard_commit"]
    anti_ad_commit = parsed["anti_ad_commit"]
    coolapk_1007_reward_commit = parsed["coolapk_1007_reward_commit"]
    if not isinstance(adguard_source, Path):
        raise TypeError
    if not isinstance(anti_ad_source, Path):
        raise TypeError
    if not isinstance(coolapk_1007_reward_source, Path):
        raise TypeError
    if not isinstance(output, Path):
        raise TypeError
    if not isinstance(adguard_commit, str):
        raise TypeError
    if not isinstance(anti_ad_commit, str):
        raise TypeError
    if not isinstance(coolapk_1007_reward_commit, str):
        raise TypeError
    return BuildArgs(
        adguard_source=adguard_source,
        anti_ad_source=anti_ad_source,
        coolapk_1007_reward_source=coolapk_1007_reward_source,
        output=output,
        adguard_commit=adguard_commit,
        anti_ad_commit=anti_ad_commit,
        coolapk_1007_reward_commit=coolapk_1007_reward_commit,
    )


def main() -> int:
    args = parse_args(sys.argv[1:])
    result = convert_repositories(
        args.adguard_source,
        args.anti_ad_source,
        args.coolapk_1007_reward_source,
        {
            UpstreamKind.ADGUARD_MAGISK: args.adguard_commit,
            UpstreamKind.ANTI_AD: args.anti_ad_commit,
            UpstreamKind.COOLAPK_1007_REWARD: args.coolapk_1007_reward_commit,
        },
    )
    write_outputs(result, args.output)
    print_summary(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
