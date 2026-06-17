from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Final

from scripts.ruleset_parser import as_ipcidr, parse_adguard_values
from scripts.ruleset_types import (
    ConversionResult,
    ConversionStats,
    RuleCollector,
    RuleKind,
    UpstreamKind,
)

COMMENT_PREFIXES: Final[tuple[str, ...]] = ("!", "#", "[")
EXCEPTION_PREFIX: Final[str] = "@@"
MIN_QUOTED_LENGTH: Final[int] = 2
OUTPUT_PREFIX: Final[str] = "adrules_ultra"


def convert_repositories(
    adguard_source_dir: Path,
    anti_ad_source_dir: Path,
    coolapk_1007_reward_source: Path,
    upstream_commits: dict[UpstreamKind, str],
) -> ConversionResult:
    collectors: dict[RuleKind, RuleCollector] = {kind: RuleCollector() for kind in RuleKind}
    stats: dict[RuleKind, ConversionStats] = {kind: ConversionStats() for kind in RuleKind}

    parse_adguard_magisk(adguard_source_dir, collectors, stats)
    parse_anti_ad(anti_ad_source_dir, collectors, stats)
    parse_coolapk_1007_reward(coolapk_1007_reward_source, collectors, stats)

    return ConversionResult(
        buckets={kind: collector.freeze() for kind, collector in collectors.items()},
        stats=stats,
        upstream_commits=upstream_commits,
    )


def parse_adguard_magisk(
    source_dir: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    filters_dir = source_dir / "Adguardhome" / "bin" / "data" / "filters"
    if not filters_dir.is_dir():
        message = f"missing rule directory: {filters_dir}"
        raise FileNotFoundError(message)

    parse_file(filters_dir / "1721861846.txt", RuleKind.ADS, collectors, stats)
    parse_file(filters_dir / "1735560833.txt", RuleKind.MALWARE, collectors, stats)
    parse_file(filters_dir / "1721861844.txt", RuleKind.ALLOW, collectors, stats)
    parse_user_rules(source_dir / "Adguardhome" / "bin" / "AdGuardHome.yaml", collectors, stats)


def parse_anti_ad(
    source_dir: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    parse_file(source_dir / "anti-ad-adguard.txt", RuleKind.ADS, collectors, stats)


def parse_coolapk_1007_reward(
    source_path: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    parse_file(source_path, RuleKind.ADS, collectors, stats)


def parse_file(
    path: Path,
    default_kind: RuleKind,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    if not path.is_file():
        message = f"missing rule file: {path}"
        raise FileNotFoundError(message)
    with path.open("r", encoding="utf-8", errors="replace") as rule_file:
        for raw_line in rule_file:
            parse_rule(raw_line.rstrip("\n"), default_kind, collectors, stats)


def parse_user_rules(
    config_path: Path,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    if not config_path.is_file():
        message = f"missing AdGuardHome config: {config_path}"
        raise FileNotFoundError(message)
    in_user_rules = False
    with config_path.open("r", encoding="utf-8", errors="replace") as config_file:
        for raw_line in config_file:
            line = raw_line.rstrip("\n")
            if line == "user_rules:":
                in_user_rules = True
                continue
            if in_user_rules and line and not line.startswith("  - "):
                break
            if not in_user_rules or not line.startswith("  - "):
                continue
            parse_rule(unquote_yaml_list_value(line[4:]), RuleKind.ADS, collectors, stats)


def unquote_yaml_list_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= MIN_QUOTED_LENGTH and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= MIN_QUOTED_LENGTH and value[0] == '"' and value[-1] == '"':
        return bytes(value[1:-1], "utf-8").decode("unicode_escape")
    return value


def parse_rule(
    raw_line: str,
    default_kind: RuleKind,
    collectors: dict[RuleKind, RuleCollector],
    stats: dict[RuleKind, ConversionStats],
) -> None:
    line = raw_line.strip()
    kind = RuleKind.ALLOW if line.startswith(EXCEPTION_PREFIX) else default_kind
    stat = stats[kind]
    stat.total += 1

    if not line or line.startswith(COMMENT_PREFIXES):
        stat.comments += 1
        return
    if line.startswith(EXCEPTION_PREFIX):
        line = line.removeprefix(EXCEPTION_PREFIX)

    parsed_values = parse_adguard_values(line, stat, allow_domain_modifier=kind is RuleKind.ALLOW)
    if not parsed_values:
        return

    for value in parsed_values:
        if ipcidr := as_ipcidr(value):
            collectors[kind].add_ipcidr(ipcidr)
            stat.ipcidr += 1
            continue
        collectors[kind].add_domain(value)
        stat.domain += 1


def write_outputs(result: ConversionResult, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for kind, buckets in result.buckets.items():
        write_lines(output_dir / f"{OUTPUT_PREFIX}_{kind.value}.txt", buckets.domains)
        write_lines(output_dir / f"{OUTPUT_PREFIX}_{kind.value}_ipcidr.txt", buckets.ipcidrs)
    write_manifest(result, output_dir / "manifest.md")


def write_lines(path: Path, lines: Iterable[str]) -> None:
    values = sorted(set(lines))
    _ = path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def write_manifest(result: ConversionResult, path: Path) -> None:
    lines = [
        "# AdRulesUltra mihomo MRS",
        "",
        "## 上游",
        "",
        f"- AdGuard Home For Magisk Mod: `{result.upstream_commits[UpstreamKind.ADGUARD_MAGISK]}`",
        f"- anti-AD: `{result.upstream_commits[UpstreamKind.ANTI_AD]}`",
        f"- Coolapk 1007 reward: `{result.upstream_commits[UpstreamKind.COOLAPK_1007_REWARD]}`",
        "",
        "- 产物语义: 多上游 DNS 广告规则到 mihomo domain/ipcidr rule-provider 的保守转换。",
        f"- 例外规则已拆为 `{OUTPUT_PREFIX}_allow.*`, 建议在 mihomo `sub-rules` 中用 `PASS` 使用。",
        "",
        "| 集合 | domain | ipcidr | 跳过 | 正则 | 修饰符 | 路径 | 模式 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for kind in RuleKind:
        stat = result.stats[kind]
        row = (
            f"| `{kind.value}` | {stat.domain} | {stat.ipcidr} | {stat.skipped} | "
            f"{stat.unsupported_regex} | {stat.unsupported_modifier} | {stat.unsupported_path} | "
            f"{stat.unsupported_pattern} |"
        )
        _ = lines.append(row)
    _ = lines.extend(
        [
            "",
            "## 规则集",
            "",
            f"- `{OUTPUT_PREFIX}_ads.mrs` / `{OUTPUT_PREFIX}_ads_ipcidr.mrs`",
            f"- `{OUTPUT_PREFIX}_malware.mrs` / `{OUTPUT_PREFIX}_malware_ipcidr.mrs`",
            f"- `{OUTPUT_PREFIX}_allow.mrs` / `{OUTPUT_PREFIX}_allow_ipcidr.mrs`",
        ],
    )
    _ = path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_summary(result: ConversionResult) -> None:
    for kind in RuleKind:
        stat = result.stats[kind]
        summary = (
            f"{kind.value}: domain={stat.domain} ipcidr={stat.ipcidr} skipped={stat.skipped} "
            f"regex={stat.unsupported_regex} modifier={stat.unsupported_modifier} "
            f"path={stat.unsupported_path} pattern={stat.unsupported_pattern} total={stat.total}"
        )
        _ = print(summary)
