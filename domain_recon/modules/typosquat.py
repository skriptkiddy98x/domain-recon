"""Lookalike domains: typos and tricks a phisher could register to imitate this domain.

Generates permutations of the name (examp1e.com, exmaple.com, example-login.com, ...)
and checks in DNS which of them actually exist.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from domain_recon.models import Finding, ModuleResult, ScanContext
from domain_recon.net import domain_exists, resolve

NAME = "typosquat"
TITLE = "Lookalike domains (typosquatting)"
SOURCE = "Generated permutations, checked in DNS"

KEYBOARD_NEIGHBORS = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg", "y": "tugh", "u": "yihj",
    "i": "uojk", "o": "ipkl", "p": "ol", "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc",
    "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
HOMOGLYPHS = {
    "o": ("0",), "l": ("1", "i"), "i": ("1", "l"), "e": ("3",), "a": ("4",), "s": ("5",),
    "g": ("q",), "q": ("g",), "u": ("v",), "v": ("u",), "m": ("rn",), "w": ("vv",), "d": ("cl",),
}
MULTI_CHAR_HOMOGLYPHS = {"rn": "m", "vv": "w", "cl": "d"}
ALTERNATIVE_TLDS = (
    "com", "net", "org", "info", "biz", "co", "io", "eu", "sk", "cz", "de", "online", "shop",
    "site", "xyz", "app",
)
PHISHING_AFFIXES = ("-login", "-secure", "-support", "-online", "-account")
PHISHING_PREFIXES = ("my", "secure-", "login-")

VALID_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    candidates = generate_lookalikes(ctx.domain)
    to_check = list(candidates.items())[: ctx.max_lookalikes_to_check]

    with ThreadPoolExecutor(max_workers=25) as pool:
        checked = list(pool.map(lambda item: check_lookalike(item[0], item[1], ctx.resolver), to_check))
    registered = [entry for entry in checked if entry]

    result.data = {
        "generated": len(candidates),
        "checked": len(to_check),
        "registered_count": len(registered),
        "registered": registered,
    }
    result.findings = analyze_lookalikes(registered)
    return result


def split_domain(domain: str) -> tuple[str, str]:
    """'example.co.uk' -> ('example', 'co.uk')"""
    label, _, suffix = domain.partition(".")
    return label, suffix


def generate_lookalikes(domain: str) -> dict[str, str]:
    """Return {lookalike_domain: technique}, most likely to be abused first."""
    label, suffix = split_domain(domain)
    candidates: dict[str, str] = {}

    def add(new_label: str, technique: str, new_suffix: str = suffix) -> None:
        candidate = f"{new_label}.{new_suffix}"
        if candidate != domain and VALID_LABEL.match(new_label):
            candidates.setdefault(candidate, technique)

    for tld in ALTERNATIVE_TLDS:
        add(label, "different TLD", tld)
    for affix in PHISHING_AFFIXES:
        add(label + affix, "added word")
    for prefix in PHISHING_PREFIXES:
        add(prefix + label, "added word")
    for i, char in enumerate(label):
        for glyph in HOMOGLYPHS.get(char, ()):
            add(label[:i] + glyph + label[i + 1:], "lookalike character")
    for sequence, replacement in MULTI_CHAR_HOMOGLYPHS.items():
        for match in re.finditer(sequence, label):
            add(label[:match.start()] + replacement + label[match.end():], "lookalike character")
    for i in range(len(label)):
        add(label[:i] + label[i + 1:], "missing letter")
    for i in range(len(label) - 1):
        add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "swapped letters")
    for i in range(len(label)):
        add(label[:i] + label[i] + label[i:], "doubled letter")
    for i, char in enumerate(label):
        for neighbor in KEYBOARD_NEIGHBORS.get(char, ""):
            add(label[:i] + neighbor + label[i + 1:], "keyboard typo")
    for i in range(1, len(label)):
        add(label[:i] + "-" + label[i:], "added hyphen")
    for i, char in enumerate(label):
        for neighbor in KEYBOARD_NEIGHBORS.get(char, ""):
            add(label[:i] + neighbor + label[i:], "extra key")
    return candidates


def check_lookalike(candidate: str, technique: str, resolver) -> dict | None:
    """Return details if the lookalike exists in DNS, otherwise None."""
    if not domain_exists(resolver, candidate):
        return None
    mx_records = resolve(resolver, candidate, "MX")
    return {
        "domain": candidate,
        "technique": technique,
        "ips": resolve(resolver, candidate, "A"),
        "can_receive_email": any(not record.endswith(" .") for record in mx_records),
    }


def analyze_lookalikes(registered: list[dict]) -> list[Finding]:
    if not registered:
        return []
    findings = [Finding(
        "low",
        f"Registered lookalike domains: {len(registered)}",
        "Not necessarily malicious: many are parked or defensive registrations by the owner. "
        "Check who owns them: " + ", ".join(entry["domain"] for entry in registered[:12])
        + (" ..." if len(registered) > 12 else ""),
    )]
    with_mail = [entry["domain"] for entry in registered if entry["can_receive_email"]]
    if with_mail:
        findings.append(Finding(
            "medium",
            f"Lookalike domains that can receive email ({len(with_mail)})",
            "Mail-enabled lookalikes can be used for phishing or to catch mistyped emails: "
            + ", ".join(with_mail[:12]) + (" ..." if len(with_mail) > 12 else ""),
        ))
    return findings
