from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from scripts.ruleset_types import ConversionStats


ADBLOCK_PREFIX: Final[str] = "||"
SAFE_DNS_MODIFIERS: Final[frozenset[str]] = frozenset({"", "important"})
URL_SCHEMES: Final[tuple[str, ...]] = ("http://", "https://", "ws://", "wss://")
HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9*_.+-]+$")
HOST_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"^(?:\|\|)?(?P<host>[A-Za-z0-9*_.+-]+)(?::[0-9]+)?(?:[/:^|]|$)")
DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$",
)
CLASH_WILDCARD_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_*.-]+$")
IPV4_VERSION: Final[int] = 4
CIDR_SEPARATOR: Final[str] = "/"
MIN_DOMAIN_LABELS: Final[int] = 2


def parse_adguard_values(line: str, stat: ConversionStats, *, allow_domain_modifier: bool) -> tuple[str, ...]:
    rule, modifiers = split_modifiers(line)
    if not safe_modifiers(modifiers):
        return parse_unsupported_modifier_rule(rule, stat, allow_domain_modifier=allow_domain_modifier)
    if rule.startswith("/") and rule.endswith("/"):
        mark_skipped_regex(stat)
        return ()
    return parse_adguard_rule_body(rule, stat)


def parse_unsupported_modifier_rule(
    rule: str,
    stat: ConversionStats,
    *,
    allow_domain_modifier: bool,
) -> tuple[str, ...]:
    suffix_semantics = rule.startswith(ADBLOCK_PREFIX)
    extracted = extract_host_rule(rule, has_suffix_semantics=suffix_semantics) if allow_domain_modifier else None
    if extracted is not None:
        return (extracted,)
    mark_skipped_modifier(stat)
    return ()


def parse_adguard_rule_body(rule: str, stat: ConversionStats) -> tuple[str, ...]:
    has_suffix_semantics = rule.startswith(ADBLOCK_PREFIX)
    candidate = rule.removeprefix(ADBLOCK_PREFIX).removesuffix("^").removesuffix("|").removeprefix("|")
    if normalized_cidr := as_ipcidr(candidate):
        return (normalized_cidr,)
    if "/" in candidate or ":" in candidate or "^" in candidate:
        return parse_rule_with_path_or_port(rule, stat, has_suffix_semantics=has_suffix_semantics)
    if not candidate or not HOSTNAME_RE.fullmatch(candidate):
        return skip_pattern(stat)
    if as_ipcidr(candidate) is not None:
        return (candidate,)

    normalized = normalize_domain_pattern(candidate, has_suffix_semantics=has_suffix_semantics)
    if normalized is None:
        return skip_pattern(stat)
    return (normalized,)


def parse_rule_with_path_or_port(rule: str, stat: ConversionStats, *, has_suffix_semantics: bool) -> tuple[str, ...]:
    if extracted := extract_host_rule(rule, has_suffix_semantics=has_suffix_semantics):
        return (extracted,)
    return skip_path(stat)


def split_modifiers(line: str) -> tuple[str, frozenset[str]]:
    rule, separator, modifier_text = line.partition("$")
    if not separator:
        return rule, frozenset()
    return rule, frozenset(modifier.strip() for modifier in modifier_text.split(","))


def safe_modifiers(modifiers: frozenset[str]) -> bool:
    return all(modifier.split("=", maxsplit=1)[0] in SAFE_DNS_MODIFIERS for modifier in modifiers)


def extract_host_rule(rule: str, *, has_suffix_semantics: bool) -> str | None:
    if url_host := extract_url_host_rule(rule, has_suffix_semantics=has_suffix_semantics):
        return url_host

    match = HOST_PREFIX_RE.match(rule)
    if match is None:
        return None
    host = match.group("host")
    if as_ipcidr(host) is not None:
        return host
    return normalize_domain_pattern(host, has_suffix_semantics=has_suffix_semantics)


def extract_url_host_rule(rule: str, *, has_suffix_semantics: bool) -> str | None:
    normalized_rule = rule.lstrip("|").rstrip("^|")
    if normalized_rule.startswith("blob:"):
        normalized_rule = normalized_rule.removeprefix("blob:")
    if normalized_rule.startswith("://"):
        normalized_rule = f"https{normalized_rule}"
    if not normalized_rule.startswith(URL_SCHEMES):
        return None

    split_result = urlsplit(normalized_rule)
    if split_result.hostname is None:
        return None
    host = split_result.hostname.rstrip(".")
    if as_ipcidr(host) is not None:
        return host
    return normalize_domain_pattern(host, has_suffix_semantics=has_suffix_semantics)


def normalize_domain_pattern(candidate: str, *, has_suffix_semantics: bool) -> str | None:
    domain = candidate.lower().strip(".")
    if not domain:
        return None
    if domain.startswith("*."):
        suffix = domain[2:]
        return f".{suffix}" if valid_clash_domain(suffix) or safe_clash_wildcard(suffix) else None
    if "*" in domain:
        wildcard = safe_clash_wildcard(domain)
        if wildcard is None:
            return None
        return f"+.{wildcard}" if has_suffix_semantics else wildcard
    if not valid_clash_domain(domain):
        return None
    return f"+.{domain}" if has_suffix_semantics else domain


def safe_clash_wildcard(domain: str) -> str | None:
    if not CLASH_WILDCARD_RE.fullmatch(domain):
        return None
    labels = domain.split(".")
    if len(labels) < MIN_DOMAIN_LABELS or any(not label for label in labels):
        return None
    if all(label == "*" for label in labels):
        return None
    return domain


def valid_clash_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.fullmatch(domain)) or domain == "localhost"


def as_ipcidr(value: str) -> str | None:
    try:
        if CIDR_SEPARATOR in value:
            network = ipaddress.ip_network(value, strict=False)
            return str(network)
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return f"{address}/32" if address.version == IPV4_VERSION else f"{address}/128"


def mark_skipped_modifier(stat: ConversionStats) -> None:
    stat.unsupported_modifier += 1
    stat.skipped += 1


def mark_skipped_regex(stat: ConversionStats) -> None:
    stat.unsupported_regex += 1
    stat.skipped += 1


def mark_skipped_path(stat: ConversionStats) -> tuple[str, ...]:
    stat.unsupported_path += 1
    stat.skipped += 1
    return ()


def mark_skipped_pattern(stat: ConversionStats) -> tuple[str, ...]:
    stat.unsupported_pattern += 1
    stat.skipped += 1
    return ()


def skip_path(stat: ConversionStats) -> tuple[str, ...]:
    return mark_skipped_path(stat)


def skip_pattern(stat: ConversionStats) -> tuple[str, ...]:
    return mark_skipped_pattern(stat)
