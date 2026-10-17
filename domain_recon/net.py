"""Small network helpers shared by the modules: an HTTP session and DNS lookups."""

from __future__ import annotations

import dns.exception
import dns.rdatatype
import dns.resolver
import requests

from domain_recon import __version__

USER_AGENT = f"domain-recon/{__version__} (passive OSINT research tool)"


def make_http_session() -> requests.Session:
    """HTTP session with an honest User-Agent, so site owners can see who is asking."""
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session


def make_resolver(timeout: float = 5.0) -> dns.resolver.Resolver:
    """DNS resolver that uses the system's configured name servers."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def resolve(resolver: dns.resolver.Resolver, name: str, record_type: str) -> list[str]:
    """Return the records of one type as text, or an empty list if there are none."""
    try:
        answer = resolver.resolve(name, record_type)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    return [record_to_text(record) for record in answer]


def record_to_text(record) -> str:
    """TXT records come split into quoted chunks; join them back into one string."""
    if record.rdtype == dns.rdatatype.TXT:
        return b"".join(record.strings).decode("utf-8", errors="replace")
    return record.to_text()


def domain_exists(resolver: dns.resolver.Resolver, name: str) -> bool | None:
    """True if the name exists in DNS, False if it does not, None if we can't tell."""
    try:
        resolver.resolve(name, "NS")
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    except (dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    return True
