"""Subdomains from Certificate Transparency logs.

Every publicly trusted TLS certificate is written to public CT logs, so the names on
those certificates (dev.example.com, vpn.example.com, ...) are visible to anyone.
"""

from __future__ import annotations

import secrets
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from domain_recon.models import Finding, ModuleResult, ScanContext, plural
from domain_recon.net import domain_exists, resolve

NAME = "subdomains"
TITLE = "Subdomains (Certificate Transparency)"
SOURCE = "crt.sh, CertSpotter as fallback"

CRTSH_URL = "https://crt.sh/"
CRTSH_ATTEMPTS = 3
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

SENSITIVE_KEYWORDS = {
    "admin", "backup", "beta", "citrix", "confluence", "db", "debug", "dev", "git", "gitlab",
    "grafana", "internal", "intranet", "jenkins", "jira", "kibana", "legacy", "old", "owa",
    "phpmyadmin", "qa", "rdp", "remote", "sql", "stage", "staging", "test", "uat", "vpn",
}


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    raw_names, used_source = fetch_certificate_names(ctx.domain, ctx.http, ctx.timeout)
    subdomains = extract_subdomains(raw_names, ctx.domain)

    wildcard_ips = detect_wildcard_ips(ctx.domain, ctx.resolver)
    to_check = subdomains[: ctx.max_subdomains_to_resolve]
    with ThreadPoolExecutor(max_workers=20) as pool:
        hosts = list(pool.map(lambda name: inspect_host(name, ctx, wildcard_ips), to_check))

    result.data = {
        "source_used": used_source,
        "total_found": len(subdomains),
        "wildcard_dns": sorted(wildcard_ips) or False,
        "checked_in_dns": len(to_check),
        "live": sum(host["live"] for host in hosts),
        "hosts": hosts,
        "not_checked": subdomains[ctx.max_subdomains_to_resolve:],
    }
    result.findings = analyze_subdomains(hosts, len(subdomains), wildcard_ips)
    return result


def detect_wildcard_ips(domain: str, resolver) -> set[str]:
    """If a random name resolves, the zone uses wildcard DNS and every subdomain 'exists'."""
    return set(resolve(resolver, f"wildcard-check-{secrets.token_hex(6)}.{domain}", "A"))


def inspect_host(name: str, ctx: ScanContext, wildcard_ips: set[str]) -> dict:
    """Resolve one subdomain and flag anything interesting about it."""
    ips = resolve(ctx.resolver, name, "A")
    return {
        "name": name,
        "ips": ips,
        "live": bool(ips) and not set(ips) <= wildcard_ips,
        "sensitive": is_sensitive_name(name, ctx.domain),
        "dangling_cname": None if ips else find_dangling_cname(name, ctx.resolver),
    }


def fetch_certificate_names(domain: str, http: requests.Session, timeout: float) -> tuple[list[str], str]:
    """crt.sh is the most complete source but often overloaded: retry it, then fall back to CertSpotter."""
    crtsh_problem = "returned no certificates"
    for attempt in range(CRTSH_ATTEMPTS):
        try:
            names = fetch_from_crtsh(domain, http, max(timeout, 60))
        except (requests.RequestException, ValueError) as exc:
            crtsh_problem = describe_error(exc)
            time.sleep(3 * (attempt + 1))
            continue
        if names:
            return names, "crt.sh"
        break
    try:
        return fetch_from_certspotter(domain, http, timeout), "CertSpotter"
    except requests.RequestException as exc:
        raise RuntimeError(
            f"crt.sh {crtsh_problem} and CertSpotter {describe_error(exc)}. "
            "Both are free public services; try again later."
        ) from exc


def describe_error(exc: Exception) -> str:
    """Short, readable reason such as 'answered HTTP 502' or 'timed out'."""
    response = getattr(exc, "response", None)
    if response is not None:
        return f"answered HTTP {response.status_code}"
    if isinstance(exc, requests.Timeout):
        return "timed out"
    return f"failed ({type(exc).__name__})"


def fetch_from_crtsh(domain: str, http: requests.Session, timeout: float) -> list[str]:
    response = http.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout)
    response.raise_for_status()
    return [entry.get("name_value", "") for entry in response.json()]


def fetch_from_certspotter(domain: str, http: requests.Session, timeout: float, max_pages: int = 5) -> list[str]:
    """CertSpotter returns 100 certificates per page; 'after' asks for the next page."""
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    names = []
    for _page in range(max_pages):
        response = http.get(CERTSPOTTER_URL, params=params, timeout=timeout)
        response.raise_for_status()
        issuances = response.json()
        if not issuances:
            break
        names += [name for issuance in issuances for name in issuance.get("dns_names", [])]
        params["after"] = issuances[-1]["id"]
    return names


def extract_subdomains(raw_names: list[str], domain: str) -> list[str]:
    """Clean up certificate names: one name per line, drop wildcards and foreign domains."""
    found = set()
    for raw in raw_names:
        for name in raw.splitlines():
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name != domain and name.endswith("." + domain):
                found.add(name)
    return sorted(found)


def is_sensitive_name(name: str, domain: str) -> bool:
    """True for names like dev.example.com, vpn2.example.com or jenkins-old.example.com."""
    prefix = name[: -len(domain) - 1]
    tokens = prefix.replace("-", ".").replace("_", ".").split(".")
    return any(token.rstrip("0123456789") in SENSITIVE_KEYWORDS for token in tokens)


def find_dangling_cname(name: str, resolver) -> str | None:
    """A CNAME that points to a name that no longer exists can enable subdomain takeover."""
    targets = resolve(resolver, name, "CNAME")
    if not targets:
        return None
    target = targets[0].rstrip(".")
    return target if domain_exists(resolver, target) is False else None


def analyze_subdomains(hosts: list[dict], total_found: int, wildcard_ips: set[str] = frozenset()) -> list[Finding]:
    findings = [Finding(
        "info",
        f"{plural(total_found, 'subdomain')} found in Certificate Transparency logs",
        f"{sum(host['live'] for host in hosts)} of the {len(hosts)} checked still resolve to their own IP.",
    )]
    if wildcard_ips:
        findings.append(Finding(
            "info",
            "Wildcard DNS is enabled",
            f"Any subdomain resolves to {', '.join(sorted(wildcard_ips))}. "
            "Hosts that only answer through the wildcard are not counted as live.",
        ))

    dangling = [host for host in hosts if host["dangling_cname"]]
    if dangling:
        findings.append(Finding(
            "high",
            f"Possible subdomain takeover ({len(dangling)})",
            "CNAME points to a name that does not exist: "
            + ", ".join(f"{host['name']} -> {host['dangling_cname']}" for host in dangling[:10]),
        ))

    sensitive_live = [host["name"] for host in hosts if host["sensitive"] and host["live"]]
    if sensitive_live:
        findings.append(Finding(
            "medium",
            f"Potentially sensitive subdomains are reachable ({len(sensitive_live)})",
            ", ".join(sensitive_live[:15]) + (" ..." if len(sensitive_live) > 15 else ""),
        ))
    return findings
