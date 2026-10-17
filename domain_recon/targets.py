"""Turn user input (domains, URLs, pasted lists, files) into a clean list of domains to scan."""

from __future__ import annotations

import re
from pathlib import Path

import tldextract

HOST_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
LIST_SEPARATORS = re.compile(r"[\s,;]+")

# Uses the copy of the Public Suffix List bundled with tldextract: no downloads, no cache files.
_public_suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def normalize_host(raw: str) -> str:
    """'https://www.Example.com/path' -> 'example.com'. Internationalised names become punycode."""
    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = re.split(r"[/?#]", value, maxsplit=1)[0]
    value = value.rsplit("@", 1)[-1].split(":")[0].rstrip(".")
    value = value.removeprefix("www.")
    try:
        value = value.encode("idna").decode("ascii")  # žilina.sk -> xn--ilina-tib.sk
    except UnicodeError as exc:
        raise ValueError(f"'{raw}' is not a valid domain name") from exc
    if not HOST_PATTERN.match(value):
        raise ValueError(f"'{raw}' is not a valid domain name")
    return value


def registrable_domain(host: str) -> str:
    """The part of a host name that someone actually registers.

    'shop.example.co.uk' -> 'example.co.uk'
    'name.github.io'     -> 'name.github.io'  (each GitHub Pages site belongs to someone else)
    """
    parts = _public_suffixes(host, include_psl_private_domains=True)
    if not parts.domain:  # the host is itself a hosting suffix such as 'github.io'
        parts = _public_suffixes(host, include_psl_private_domains=False)
    if not parts.suffix:
        raise ValueError(f"'{host}' does not end in a known top-level domain")
    if not parts.domain:
        raise ValueError(f"'{host}' is a public suffix, not a domain someone owns")
    return f"{parts.domain}.{parts.suffix}"


def normalize_domain(raw: str) -> str:
    return registrable_domain(normalize_host(raw))


def split_domain_list(text: str) -> list[str]:
    """Split pasted text or a file into entries: one per line or separated by spaces,
    commas or semicolons. Everything after '#' on a line is a comment."""
    entries = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        entries += [entry for entry in LIST_SEPARATORS.split(line) if entry]
    return entries


def read_domain_file(path: Path) -> list[str]:
    return split_domain_list(path.read_text(encoding="utf-8-sig"))


def prepare_targets(raw_entries: list[str]) -> tuple[list[str], list[str]]:
    """Normalise every entry. Returns (unique domains in input order, notes for the user)."""
    domains: list[str] = []
    notes: list[str] = []
    for raw in raw_entries:
        try:
            host = normalize_host(raw)
            domain = registrable_domain(host)
        except ValueError as exc:
            notes.append(f"skipped: {exc}")
            continue
        if host != domain:
            notes.append(f"{host} is a subdomain, scanning {domain} instead")
        if domain not in domains:
            domains.append(domain)
    return domains, notes
