from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RuleKind(StrEnum):
    ADS = "ads"
    ALLOW = "allow"
    MALWARE = "malware"


class UpstreamKind(StrEnum):
    ADGUARD_MAGISK = "adguard-magisk"
    ANTI_AD = "anti-ad"
    COOLAPK_1007_REWARD = "coolapk-1007-reward"


@dataclass(frozen=True, slots=True)
class RuleBuckets:
    domains: frozenset[str] = frozenset()
    ipcidrs: frozenset[str] = frozenset()


@dataclass(slots=True)
class RuleCollector:
    domains: set[str] = field(default_factory=set)
    ipcidrs: set[str] = field(default_factory=set)

    def add_domain(self, domain: str) -> None:
        self.domains.add(domain)

    def add_ipcidr(self, ipcidr: str) -> None:
        self.ipcidrs.add(ipcidr)

    def freeze(self) -> RuleBuckets:
        return RuleBuckets(domains=frozenset(self.domains), ipcidrs=frozenset(self.ipcidrs))


@dataclass(slots=True)
class ConversionStats:
    total: int = 0
    domain: int = 0
    ipcidr: int = 0
    comments: int = 0
    skipped: int = 0
    unsupported_regex: int = 0
    unsupported_modifier: int = 0
    unsupported_path: int = 0
    unsupported_pattern: int = 0


@dataclass(frozen=True, slots=True)
class ConversionResult:
    buckets: dict[RuleKind, RuleBuckets]
    stats: dict[RuleKind, ConversionStats]
    upstream_commits: dict[UpstreamKind, str]
