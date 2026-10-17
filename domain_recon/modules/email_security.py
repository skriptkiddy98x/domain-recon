"""Email security: can someone send email that looks like it comes from this domain?

SPF   lists the servers allowed to send mail for the domain.
DKIM  signs outgoing mail with a key published in DNS.
DMARC tells receivers what to do when SPF/DKIM checks fail (nothing, spam folder, reject).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from domain_recon.models import Finding, ModuleResult, ScanContext
from domain_recon.net import resolve

NAME = "email"
TITLE = "Email security (SPF, DKIM, DMARC)"
SOURCE = "DNS"

# DKIM selectors are arbitrary names; these are the ones big providers use by default.
COMMON_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "dkim",
    "mail", "smtp", "key1", "key2", "sig1", "mandrill", "mailjet", "everlytickey1", "cm",
    "zoho", "protonmail", "protonmail2", "fm1", "fm2", "mxvault",
)

# Substrings in MX hosts or SPF includes that identify the email provider.
EMAIL_PROVIDER_HINTS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "zoho": "Zoho Mail",
    "pphosted.com": "Proofpoint",
    "mimecast": "Mimecast",
    "messagelabs": "Broadcom Email Security",
    "barracudanetworks": "Barracuda",
    "protonmail": "Proton Mail",
    "sendgrid.net": "SendGrid",
    "mailgun.org": "Mailgun",
    "mcsv.net": "Mailchimp",
    "mandrillapp.com": "Mailchimp Transactional",
    "amazonses.com": "Amazon SES",
    "salesforce.com": "Salesforce",
    "mktomail.com": "Marketo",
    "hubspotemail.net": "HubSpot",
    "sendinblue.com": "Brevo",
    "brevo.com": "Brevo",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
}

SPF_LOOKUP_LIMIT = 10


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    mx_records = resolve(ctx.resolver, ctx.domain, "MX")
    spf_records = [r for r in resolve(ctx.resolver, ctx.domain, "TXT") if r.lower().startswith("v=spf1")]
    dmarc_records = [
        r for r in resolve(ctx.resolver, f"_dmarc.{ctx.domain}", "TXT")
        if r.lower().startswith("v=dmarc1")
    ]
    dkim_selectors = find_dkim_selectors(ctx.domain, ctx.resolver)

    result.data = {
        "spoofing_risk": assess_spoofing_risk(spf_records, dmarc_records),
        "mx": mx_records,
        "providers": detect_email_providers(mx_records, spf_records),
        "spf": spf_records,
        "dmarc": dmarc_records,
        "dmarc_policy": parse_tags(dmarc_records[0]) if len(dmarc_records) == 1 else {},
        "dkim_selectors_found": dkim_selectors,
    }
    result.findings = (
        analyze_spf(spf_records)
        + analyze_dmarc(dmarc_records)
        + analyze_dkim(dkim_selectors, has_mx=bool(mx_records))
    )
    return result


# --- SPF -------------------------------------------------------------------------------

def parse_spf(record: str) -> dict:
    """Split an SPF record into its 'all' policy, includes and the number of DNS lookups."""
    all_policy = None
    redirect = None
    includes = []
    dns_lookups = 0
    for term in record.split()[1:]:
        term = term.lower()
        qualifier = term[0] if term[0] in "+-~?" else "+"
        mechanism = term.lstrip("+-~?")

        if mechanism == "all":
            all_policy = f"{qualifier}all"
        elif mechanism.startswith("include:"):
            includes.append(mechanism.removeprefix("include:"))
            dns_lookups += 1
        elif mechanism.startswith("redirect="):
            redirect = mechanism.removeprefix("redirect=")
            dns_lookups += 1
        elif mechanism in ("a", "mx", "ptr") or mechanism.startswith(
            ("a:", "a/", "mx:", "mx/", "ptr:", "exists:")
        ):
            dns_lookups += 1
    return {"all": all_policy, "redirect": redirect, "includes": includes, "dns_lookups": dns_lookups}


def analyze_spf(spf_records: list[str]) -> list[Finding]:
    if not spf_records:
        return [Finding(
            "high",
            "No SPF record",
            "Receiving mail servers cannot check which servers may send mail for this domain.",
        )]
    if len(spf_records) > 1:
        return [Finding(
            "medium",
            "Multiple SPF records",
            "RFC 7208 treats more than one SPF record as a permanent error, so SPF is broken.",
        )]

    spf = parse_spf(spf_records[0])
    findings = []
    if spf["all"] == "+all":
        findings.append(Finding("high", "SPF allows every server (+all)", "Anyone can pass the SPF check."))
    elif spf["all"] == "?all":
        findings.append(Finding("medium", "SPF policy is neutral (?all)", "Failing mail is not penalised."))
    elif spf["all"] == "~all":
        findings.append(Finding(
            "low",
            "SPF policy is soft-fail (~all)",
            "Spoofed mail is usually still delivered, often to spam. '-all' is stricter.",
        ))
    elif spf["all"] is None and not spf["redirect"]:
        findings.append(Finding("medium", "SPF record has no 'all' mechanism", spf_records[0]))

    if spf["dns_lookups"] > SPF_LOOKUP_LIMIT:
        findings.append(Finding(
            "medium",
            f"SPF needs {spf['dns_lookups']} DNS lookups (limit is {SPF_LOOKUP_LIMIT})",
            "Receivers may stop evaluating SPF and treat it as an error.",
        ))
    return findings


# --- DMARC -----------------------------------------------------------------------------

def parse_tags(record: str) -> dict[str, str]:
    """DMARC and DKIM records share one syntax.

    'v=DMARC1; p=reject; rua=mailto:x@y' -> {'v': 'DMARC1', 'p': 'reject', 'rua': ...}
    """
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def analyze_dmarc(dmarc_records: list[str]) -> list[Finding]:
    if not dmarc_records:
        return [Finding(
            "high",
            "No DMARC record",
            "Receivers have no instructions for mail that fails SPF/DKIM, "
            "so the domain is easy to spoof in phishing emails.",
        )]
    if len(dmarc_records) > 1:
        return [Finding("medium", "Multiple DMARC records", "Receivers will ignore DMARC entirely.")]

    tags = parse_tags(dmarc_records[0])
    policy = tags.get("p", "").lower()
    findings = []
    if policy not in ("none", "quarantine", "reject"):
        findings.append(Finding("medium", "DMARC record has no valid policy (p=)", dmarc_records[0]))
    elif policy == "none":
        findings.append(Finding(
            "medium",
            "DMARC policy is 'none' (monitoring only)",
            "Spoofed mail is still delivered normally. 'quarantine' or 'reject' enforces protection.",
        ))
    elif policy == "quarantine":
        findings.append(Finding(
            "low",
            "DMARC policy is 'quarantine'",
            "Spoofed mail goes to spam. 'reject' blocks it.",
        ))

    if tags.get("sp", "").lower() == "none" and policy in ("quarantine", "reject"):
        findings.append(Finding("low", "DMARC subdomain policy is 'none'", "Subdomains can still be spoofed."))

    pct = tags.get("pct", "100")
    if pct.isdigit() and int(pct) < 100:
        findings.append(Finding("low", f"DMARC applies to only {pct}% of mail", dmarc_records[0]))

    if "rua" not in tags:
        findings.append(Finding(
            "low",
            "No DMARC aggregate reports (rua)",
            "The owner does not receive reports about who sends mail in the domain's name.",
        ))
    return findings


# --- DKIM ------------------------------------------------------------------------------

def find_dkim_selectors(domain: str, resolver) -> list[str]:
    def has_dkim_key(selector: str) -> bool:
        records = resolve(resolver, f"{selector}._domainkey.{domain}", "TXT")
        return any(is_active_dkim_key(record) for record in records)

    with ThreadPoolExecutor(max_workers=10) as pool:
        found = pool.map(has_dkim_key, COMMON_DKIM_SELECTORS)
    return [selector for selector, exists in zip(COMMON_DKIM_SELECTORS, found, strict=True) if exists]


def is_active_dkim_key(record: str) -> bool:
    """A DKIM record with an empty public key ('p=') means the key was revoked."""
    return bool(parse_tags(record).get("p"))


def analyze_dkim(selectors: list[str], has_mx: bool) -> list[Finding]:
    if selectors or not has_mx:
        return []
    return [Finding(
        "info",
        "No DKIM key found on common selectors",
        "Selectors can have any name, so this does not prove DKIM is missing.",
    )]


# --- Summary ---------------------------------------------------------------------------

def assess_spoofing_risk(spf_records: list[str], dmarc_records: list[str]) -> str:
    """Rough answer to 'can I fake an email from this domain?': high, medium or low."""
    policy = parse_tags(dmarc_records[0]).get("p", "").lower() if len(dmarc_records) == 1 else ""
    spf_all = parse_spf(spf_records[0])["all"] if len(spf_records) == 1 else None
    if policy in ("quarantine", "reject"):
        return "low"
    if spf_all == "-all":
        return "medium"
    return "high"


def detect_email_providers(mx_records: list[str], spf_records: list[str]) -> list[str]:
    haystack = " ".join(mx_records + spf_records).lower()
    return sorted({provider for hint, provider in EMAIL_PROVIDER_HINTS.items() if hint in haystack})
