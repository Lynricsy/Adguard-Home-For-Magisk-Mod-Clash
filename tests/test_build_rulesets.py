from __future__ import annotations

from pathlib import Path

from scripts.ruleset_core import convert_repositories, parse_rule
from scripts.ruleset_parser import parse_adguard_values
from scripts.ruleset_stats import build_stats_payload
from scripts.ruleset_types import (
    ConversionStats,
    RuleCollector,
    RuleKind,
    UpstreamKind,
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


def test_parse_hosts_block_rule_when_sinkhole_entry() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("0.0.0.0 ads.example.com", RuleKind.ADS, collectors, stats)
    parse_rule("127.0.0.1 localhost", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"ads.example.com"}
    assert stats[RuleKind.ADS].domain == 1


def test_parse_hosts_block_rule_when_inline_comment_has_domain_text() -> None:
    collectors = {kind: RuleCollector() for kind in RuleKind}
    stats = {kind: ConversionStats() for kind in RuleKind}

    parse_rule("0.0.0.0 ads.example.com # note.example.com", RuleKind.ADS, collectors, stats)

    assert collectors[RuleKind.ADS].domains == {"ads.example.com"}


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


def test_convert_repositories_when_multiple_upstreams_have_rules(tmp_path: Path) -> None:
    adguard_source = tmp_path / "adguard"
    anti_ad_source = tmp_path / "anti-ad"
    reward_source = tmp_path / "reward.txt"
    filters_dir = adguard_source / "Adguardhome" / "bin" / "data" / "filters"
    filters_dir.mkdir(parents=True)
    (adguard_source / "Adguardhome" / "bin").mkdir(exist_ok=True)
    _ = (filters_dir / "1721861846.txt").write_text("||ads.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1735560833.txt").write_text("||bad.example.com^\n", encoding="utf-8")
    _ = (filters_dir / "1721861844.txt").write_text("@@||safe.example.com^\n", encoding="utf-8")
    _ = (adguard_source / "Adguardhome" / "bin" / "AdGuardHome.yaml").write_text(
        "user_rules:\n  - '||custom.example.com^'\n",
        encoding="utf-8",
    )
    anti_ad_source.mkdir()
    _ = (anti_ad_source / "anti-ad-adguard.txt").write_text(
        "@@||anti-safe.example.com^\n||ads.example.com^\n||anti.example.com^\n",
        encoding="utf-8",
    )
    _ = reward_source.write_text(
        "#@coolapk 1007\n127.0.0.1 localhost\n0.0.0.0 reward.example.com\n",
        encoding="utf-8",
    )

    result = convert_repositories(
        adguard_source,
        anti_ad_source,
        reward_source,
        {
            UpstreamKind.ADGUARD_MAGISK: "adguard-sha",
            UpstreamKind.ANTI_AD: "anti-sha",
            UpstreamKind.COOLAPK_1007_REWARD: "reward-sha256",
        },
    )

    assert result.buckets[RuleKind.ADS].domains == {
        "+.ads.example.com",
        "+.anti.example.com",
        "+.custom.example.com",
        "reward.example.com",
    }
    assert result.buckets[RuleKind.ALLOW].domains == {
        "+.anti-safe.example.com",
        "+.safe.example.com",
    }
    assert result.buckets[RuleKind.MALWARE].domains == {"+.bad.example.com"}
    assert result.upstream_commits[UpstreamKind.ADGUARD_MAGISK] == "adguard-sha"
    assert result.upstream_commits[UpstreamKind.ANTI_AD] == "anti-sha"
    assert result.upstream_commits[UpstreamKind.COOLAPK_1007_REWARD] == "reward-sha256"


def test_build_stats_payload_when_release_assets_exist(tmp_path: Path) -> None:
    ads_domain_count = 2
    ads_ipcidr_count = 1
    total_rule_count = 5
    ads_mrs_bytes = 1536

    _ = (tmp_path / "adrules_ultra_ads.txt").write_text("+.ads.example\n+.ads-two.example\n", encoding="utf-8")
    _ = (tmp_path / "adrules_ultra_ads_ipcidr.txt").write_text("203.0.113.1/32\n", encoding="utf-8")
    _ = (tmp_path / "adrules_ultra_allow.txt").write_text("+.safe.example\n", encoding="utf-8")
    _ = (tmp_path / "adrules_ultra_allow_ipcidr.txt").write_text("", encoding="utf-8")
    _ = (tmp_path / "adrules_ultra_malware.txt").write_text("+.bad.example\n", encoding="utf-8")
    _ = (tmp_path / "adrules_ultra_malware_ipcidr.txt").write_text("", encoding="utf-8")
    _ = (tmp_path / "adrules_ultra_ads.mrs").write_bytes(b"a" * ads_mrs_bytes)
    _ = (tmp_path / "adrules_ultra_ads_ipcidr.mrs").write_bytes(b"ip")
    _ = (tmp_path / "adrules_ultra_allow.mrs").write_bytes(b"allow")
    _ = (tmp_path / "adrules_ultra_malware.mrs").write_bytes(b"malware")

    payload = build_stats_payload(tmp_path)

    assert payload["rules"]["ads"]["domains"] == ads_domain_count
    assert payload["rules"]["ads"]["ipcidrs"] == ads_ipcidr_count
    assert payload["totals"]["total"] == total_rule_count
    assert payload["badges"] == {
        "ads_domains": "2",
        "allow_domains": "1",
        "malware_domains": "1",
        "total_rules": "5",
        "ads_mrs_size": "2 KiB",
    }
    assert payload["mrs"]["ads"]["bytes"] == ads_mrs_bytes
    assert "allow_ipcidr" not in payload["mrs"]
