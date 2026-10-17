"""Domain registration: who the registrar is and when the domain was created / expires."""

from __future__ import annotations

import re
import socket
from datetime import date, datetime, timezone

import requests

from domain_recon.models import Finding, ModuleResult, ScanContext

NAME = "registration"
TITLE = "Domain registration"
SOURCE = "RDAP via rdap.org (WHOIS fallback)"

RDAP_URL = "https://rdap.org/domain/{domain}"
IANA_WHOIS_SERVER = "whois.iana.org"

WHOIS_FIELD_PATTERNS = {
    "registrar": r"^\s*(?:Registrar|Registrar Name|Sponsoring Registrar)\s*:\s*(.+)$",
    "created": r"^\s*(?:Creation Date|Created On|Created|Registered|Registration Time)\s*:\s*(.+)$",
    "expires": r"^\s*(?:Registry Expiry Date|Expiration Date|Expiry Date|Valid Until|"
    r"paid-till|Expires On|Expires)\s*:\s*(.+)$",
    "updated": r"^\s*(?:Updated Date|Last Updated|Last Modified|Updated|changed)\s*:\s*(.+)$",
}
WHOIS_NAMESERVER_PATTERN = r"^\s*(?:Name Server|Nameserver|nserver)\s*:\s*(\S+)"


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    try:
        info = fetch_rdap(ctx.domain, ctx.http, ctx.timeout)
        info["source"] = "RDAP"
    except (requests.RequestException, ValueError):
        info = fetch_whois(ctx.domain, ctx.timeout)
        info["source"] = "WHOIS"

    now = datetime.now(timezone.utc)
    created = parse_date(info.get("created"))
    info["age_days"] = (now - created).days if created else None

    result.data = info
    result.findings = analyze_registration(info, now)
    return result


# --- RDAP (the modern, structured replacement for WHOIS) -------------------------------

def fetch_rdap(domain: str, http: requests.Session, timeout: float) -> dict:
    response = http.get(
        RDAP_URL.format(domain=domain),
        headers={"Accept": "application/rdap+json"},
        timeout=timeout,
    )
    if response.status_code == 404:
        raise ValueError(f"No RDAP service for {domain}")
    response.raise_for_status()
    return parse_rdap(response.json())


def parse_rdap(payload: dict) -> dict:
    events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events", [])}
    registrar = None
    for entity in payload.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = vcard_full_name(entity) or entity.get("handle")
    return {
        "registrar": registrar,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "status": payload.get("status", []),
        "nameservers": sorted(ns.get("ldhName", "").lower() for ns in payload.get("nameservers", [])),
        "dnssec": payload.get("secureDNS", {}).get("delegationSigned"),
    }


def vcard_full_name(entity: dict) -> str | None:
    """RDAP stores contact names in jCard format: ["vcard", [["fn", {}, "text", "Name"], ...]]."""
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for item in vcard[1]:
        if item and item[0] == "fn":
            return item[3]
    return None


# --- WHOIS (plain text over TCP port 43, used when a TLD has no RDAP) ------------------

def fetch_whois(domain: str, timeout: float) -> dict:
    tld = domain.rsplit(".", 1)[-1]
    iana_answer = whois_query(IANA_WHOIS_SERVER, tld, timeout)
    match = re.search(r"^whois:\s*(\S+)", iana_answer, re.MULTILINE)
    if not match:
        raise ValueError(f"No WHOIS server is known for .{tld}")
    return parse_whois(whois_query(match.group(1), domain, timeout))


def whois_query(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(f"{query}\r\n".encode())
        chunks = []
        while chunk := sock.recv(4096):
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_whois(raw: str) -> dict:
    info: dict = {}
    for field_name, pattern in WHOIS_FIELD_PATTERNS.items():
        match = re.search(pattern, raw, re.MULTILINE | re.IGNORECASE)
        info[field_name] = match.group(1).strip() if match else None
    nameservers = re.findall(WHOIS_NAMESERVER_PATTERN, raw, re.MULTILINE | re.IGNORECASE)
    info["nameservers"] = sorted({ns.lower().rstrip(".") for ns in nameservers})
    return info


# --- Interpretation --------------------------------------------------------------------

def parse_date(value: str | None) -> datetime | None:
    """Parse the many date formats registries use. Returns a UTC datetime or None."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.combine(date.fromisoformat(text[:10]), datetime.min.time())
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def analyze_registration(info: dict, now: datetime) -> list[Finding]:
    findings = []

    expires = parse_date(info.get("expires"))
    if expires:
        days_left = (expires - now).days
        if days_left < 0:
            findings.append(Finding("high", "Domain registration has expired", info["expires"]))
        elif days_left <= 30:
            findings.append(Finding(
                "high",
                f"Domain expires in {days_left} days",
                "An expired domain can be re-registered by anyone, including attackers.",
            ))

    created = parse_date(info.get("created"))
    if created and (now - created).days <= 90:
        findings.append(Finding(
            "medium",
            f"Recently registered domain ({(now - created).days} days old)",
            "Newly registered domains are a common indicator in phishing investigations.",
        ))

    if info.get("dnssec") is False:
        findings.append(Finding(
            "low",
            "DNSSEC is not enabled",
            "DNS answers for this domain are not cryptographically signed.",
        ))

    statuses = [status.lower().replace(" ", "") for status in info.get("status") or []]
    if statuses and not any("transferprohibited" in status for status in statuses):
        findings.append(Finding(
            "low",
            "Domain is not transfer-locked",
            "Without a transfer lock, the domain is easier to hijack via a fraudulent transfer.",
        ))
    return findings
