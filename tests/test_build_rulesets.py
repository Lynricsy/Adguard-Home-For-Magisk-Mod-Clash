from __future__ import annotations

from scripts.ruleset_core import parse_rule
from scripts.ruleset_parser import parse_adguard_values
from scripts.ruleset_types import (
    ConversionStats,
    RuleCollector,
    RuleKind,
)


def test_parse_domain_block_rule_when_adguard_suffix_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||Example.COM^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.example.com"}
    assert stats[RuleKind.ADS].domain == 1


def test_parse_allow_rule_when_exception_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@||safe.example.com^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"+.safe.example.com"}
    assert collectors[RuleKind.ADS].domains == set()


def test_parse_ip_rule_when_ipv4_literal() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||203.0.113.1^", RuleKind.MALWARE, collectors, stats)

    assert collectors[RuleKind.MALWARE].ipcidrs == {"203.0.113.1/32"}


def test_parse_ipcidr_rule_when_cidr_literal() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||216.239.35.0/24^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].ipcidrs == {"216.239.35.0/24"}


def test_parse_domain_rule_when_host_has_path() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||example.com/path.js^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.example.com"}
    assert stats[RuleKind.ADS].unsupported_path == 0


def test_parse_domain_rule_when_path_contains_url() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@||ib.adnxs.com/getuid?http://*.pch.com/", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"+.ib.adnxs.com"}


def test_parse_domain_rule_when_rule_starts_with_scheme_relative_url() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@://www.fedex.com/Tracking?", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"www.fedex.com"}


def test_parse_domain_rule_when_rule_starts_with_blob_url() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@|blob:https://www.twitch.tv", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"www.twitch.tv"}


def test_parse_allow_domain_when_exception_with_http_url_modifier() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@https://media.amazon.map.fastly.net^$script", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"media.amazon.map.fastly.net"}


def test_parse_allow_domain_when_exception_with_websocket_url_modifier() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@ws://localhost^$stealth,domain=play.sooplive.co.kr", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"localhost"}


def test_parse_domain_rule_when_host_has_port() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||ad.example.com:8443^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.ad.example.com"}


def test_parse_domain_rule_when_safe_wildcard_suffix_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||ads*-normal*.zijieapi.com^$important", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.ads*-normal*.zijieapi.com"}


def test_parse_domain_rule_when_wildcard_label_suffix_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||xbox.*.microsoft.com^", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"+.xbox.*.microsoft.com"}


def test_parse_allow_domain_when_exception_with_modifier_has_host() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@||cdn.example.com/path.js$script,domain=site.example", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == {"+.cdn.example.com"}


def test_skip_allow_rule_when_domain_modifier_has_no_host() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("@@*$script,domain=example.com", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ALLOW].domains == set()
    assert stats[RuleKind.ALLOW].unsupported_modifier == 1


def test_skip_rule_when_pure_path_specific_rule() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("/path-only.js", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == set()
    assert stats[RuleKind.ADS].unsupported_path == 1


def test_skip_rule_when_dns_modifier_cannot_be_represented_by_mrs() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("||example.com^$dnstype=AAAA", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == set()
    assert stats[RuleKind.ADS].unsupported_modifier == 1


def test_parse_adguard_values_when_domain_modifier_not_allowed() -> None:
    stat = ConversionStats()

    values = parse_adguard_values("*$domain=example.com", stat, allow_domain_modifier=False)

    assert values == ()
    assert stat.unsupported_modifier == 1
