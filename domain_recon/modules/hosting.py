"""Hosting: which IP addresses serve the domain and which network (ASN) owns them."""

from __future__ import annotations

import dns.reversename

from domain_recon.models import Finding, ModuleResult, ScanContext
from domain_recon.net import resolve

NAME = "hosting"
TITLE = "Hosting & network owner"
SOURCE = "Team Cymru IP-to-ASN service (over DNS), reverse DNS"

# Substrings of network owner names that indicate a CDN or large cloud provider.
KNOWN_PROVIDERS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "amazon": "Amazon Web Services",
    "google": "Google Cloud",
    "microsoft": "Microsoft Azure",
    "incapsula": "Imperva",
    "sucuri": "Sucuri",
    "digitalocean": "DigitalOcean",
    "hetzner": "Hetzner",
    "ovh": "OVHcloud",
    "github": "GitHub",
    "vercel": "Vercel",
    "netlify": "Netlify",
}
CDN_PROVIDERS = {"Cloudflare", "Akamai", "Fastly", "Imperva", "Sucuri"}


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    hostnames = [ctx.domain, f"www.{ctx.domain}"]

    hosts = []
    for hostname in hostnames:
        for record_type in ("A", "AAAA"):
            for ip in resolve(ctx.resolver, hostname, record_type):
                hosts.append({
                    "hostname": hostname,
                    "ip": ip,
                    "reverse_dns": reverse_dns(ip, ctx.resolver),
                    **lookup_asn(ip, ctx.resolver),
                })

    providers = sorted({provider for host in hosts if (provider := identify_provider(host))})
    result.data = {"hosts": hosts, "providers": providers}
    result.findings = analyze_hosting(hosts, providers)
    return result


def lookup_asn(ip: str, resolver) -> dict:
    """Ask Team Cymru which autonomous system announces this IP.

    8.8.4.4 becomes the query 4.4.8.8.origin.asn.cymru.com and the TXT answer looks like
    "15169 | 8.8.4.0/24 | US | arin | 1992-12-01".
    """
    reverse = dns.reversename.from_address(ip).to_text(omit_final_dot=True)
    if ":" in ip:
        query = reverse.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"
    else:
        query = reverse.removesuffix(".in-addr.arpa") + ".origin.asn.cymru.com"

    origin = resolve(resolver, query, "TXT")
    if not origin:
        return {"asn": None, "network_owner": None, "prefix": None, "country": None}

    parts = [part.strip() for part in origin[0].split("|")]
    asn = parts[0].split()[0]  # an IP can be announced by several ASNs; keep the first
    as_info = resolve(resolver, f"AS{asn}.asn.cymru.com", "TXT")
    owner = as_info[0].split("|")[-1].strip() if as_info else None
    return {
        "asn": f"AS{asn}",
        "network_owner": owner,
        "prefix": parts[1] if len(parts) > 1 else None,
        "country": parts[2] if len(parts) > 2 else None,
    }


def reverse_dns(ip: str, resolver) -> str | None:
    names = resolve(resolver, dns.reversename.from_address(ip).to_text(), "PTR")
    return names[0].rstrip(".") if names else None


def identify_provider(host: dict) -> str | None:
    haystack = f"{host.get('network_owner') or ''} {host.get('reverse_dns') or ''}".lower()
    for keyword, provider in KNOWN_PROVIDERS.items():
        if keyword in haystack:
            return provider
    return None


def analyze_hosting(hosts: list[dict], providers: list[str]) -> list[Finding]:
    if not hosts:
        return [Finding("low", "Domain has no A/AAAA records", "The domain does not point to a web server.")]

    findings = []
    owners = sorted({f"{host['network_owner']} ({host['asn']}, {host['country']})"
                     for host in hosts if host.get("network_owner")})
    if owners:
        findings.append(Finding("info", "Network owner", "; ".join(owners)))

    cdns = [provider for provider in providers if provider in CDN_PROVIDERS]
    if cdns:
        findings.append(Finding(
            "info",
            f"Served through a CDN ({', '.join(cdns)})",
            "The real origin server IP is hidden behind the CDN.",
        ))
    return findings
