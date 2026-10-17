"""DNS records: the public 'phone book' entries of the domain."""

from __future__ import annotations

from domain_recon.models import Finding, ModuleResult, ScanContext, plural
from domain_recon.net import resolve

NAME = "dns"
TITLE = "DNS records"
SOURCE = "System DNS resolver"

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

# Verification tokens that companies put in TXT records reveal which SaaS they use.
TXT_SERVICE_PREFIXES = {
    "google-site-verification=": "Google (Search Console / Workspace)",
    "ms=": "Microsoft 365",
    "facebook-domain-verification=": "Meta Business",
    "apple-domain-verification=": "Apple",
    "atlassian-domain-verification=": "Atlassian (Jira / Confluence)",
    "docusign=": "DocuSign",
    "adobe-idp-site-verification=": "Adobe",
    "stripe-verification=": "Stripe",
    "zoom_verify_": "Zoom",
    "dropbox-domain-verification=": "Dropbox",
    "miro-verification=": "Miro",
    "openai-domain-verification=": "OpenAI",
    "cisco-ci-domain-verification=": "Cisco Webex",
    "globalsign-domain-verification=": "GlobalSign",
    "onetrust-domain-verification=": "OneTrust",
    "teamviewer-sso-verification=": "TeamViewer",
    "zoho-verification=": "Zoho",
    "yandex-verification:": "Yandex",
    "have-i-been-pwned-verification=": "Have I Been Pwned (breach monitoring)",
    "brevo-code:": "Brevo",
    "hubspot-developer-verification=": "HubSpot",
}


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    records = {rtype: resolve(ctx.resolver, ctx.domain, rtype) for rtype in RECORD_TYPES}
    services = detect_services_from_txt(records["TXT"])

    result.data = {"records": records, "services_from_txt": services}
    result.findings = analyze_dns_records(records, services)
    return result


def detect_services_from_txt(txt_records: list[str]) -> list[str]:
    """Map verification tokens in TXT records to the services they belong to."""
    services = set()
    for record in txt_records:
        value = record.strip().lower()
        for prefix, service in TXT_SERVICE_PREFIXES.items():
            if value.startswith(prefix):
                services.add(service)
    return sorted(services)


def analyze_dns_records(records: dict[str, list[str]], services: list[str]) -> list[Finding]:
    findings = []
    if not records["CAA"]:
        findings.append(Finding(
            "low",
            "No CAA record",
            "Any certificate authority may issue certificates for this domain. "
            "A CAA record restricts issuance to the CAs the owner actually uses.",
        ))
    if len(records["NS"]) == 1:
        findings.append(Finding(
            "low",
            "Only one name server",
            "If that server goes down, the whole domain stops resolving.",
        ))
    if services:
        findings.append(Finding(
            "info",
            f"TXT records reveal {plural(len(services), 'third-party service')}",
            ", ".join(services),
        ))
    return findings
