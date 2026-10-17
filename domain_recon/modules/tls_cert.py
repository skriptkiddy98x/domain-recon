"""TLS certificate: who issued it, when it expires and which other names it covers."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from domain_recon.models import Finding, ModuleResult, ScanContext, plural

NAME = "tls"
TITLE = "TLS certificate"
SOURCE = "One TLS handshake on port 443 (same as opening the site in a browser)"

OUTDATED_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    last_error: Exception | None = None

    for host in (ctx.domain, f"www.{ctx.domain}"):
        try:
            connection = fetch_certificate(host, ctx.timeout)
        except ssl.SSLCertVerificationError as exc:
            result.data = {"host": host, "trusted": False, "error": exc.verify_message}
            result.findings = [Finding("high", "Certificate is not trusted", f"{host}: {exc.verify_message}")]
            return result
        except OSError as exc:
            last_error = exc
            continue

        certificate = parse_certificate(connection["cert"])
        valid_until = datetime.fromisoformat(certificate["valid_until"])
        result.data = {
            "host": host,
            "trusted": True,
            "protocol": connection["protocol"],
            "cipher": connection["cipher"],
            **certificate,
            "days_left": (valid_until - datetime.now(timezone.utc)).days,
        }
        result.findings = analyze_certificate(result.data, ctx.domain)
        return result

    result.findings = [Finding("medium", "No HTTPS on port 443", str(last_error))]
    return result


def fetch_certificate(host: str, timeout: float) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
            return {
                "cert": tls_socket.getpeercert(),
                "protocol": tls_socket.version(),
                "cipher": tls_socket.cipher()[0],
            }


def parse_certificate(cert: dict) -> dict:
    """Flatten the nested tuples that ssl.getpeercert() returns."""
    subject = dict(item for rdn in cert.get("subject", ()) for item in rdn)
    issuer = dict(item for rdn in cert.get("issuer", ()) for item in rdn)
    return {
        "subject": subject.get("commonName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "valid_from": cert_time_to_iso(cert["notBefore"]),
        "valid_until": cert_time_to_iso(cert["notAfter"]),
        "names_on_certificate": [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"],
    }


def cert_time_to_iso(value: str) -> str:
    """'Jun  1 12:00:00 2026 GMT' -> '2026-06-01T12:00:00+00:00'"""
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc).isoformat()


def analyze_certificate(data: dict, domain: str) -> list[Finding]:
    findings = []
    days_left = data["days_left"]
    if days_left < 0:
        findings.append(Finding("high", "Certificate has expired", data["valid_until"]))
    elif days_left <= 14:
        findings.append(Finding("high", f"Certificate expires in {days_left} days", data["valid_until"]))
    elif days_left <= 30:
        findings.append(Finding("medium", f"Certificate expires in {days_left} days", data["valid_until"]))

    if data.get("protocol") in OUTDATED_PROTOCOLS:
        findings.append(Finding("medium", f"Outdated TLS version ({data['protocol']})", "Use TLS 1.2 or 1.3."))

    related = sorted({
        name.removeprefix("*.") for name in data.get("names_on_certificate", [])
        if not (name.removeprefix("*.") == domain or name.endswith("." + domain))
    })
    if related:
        findings.append(Finding(
            "info",
            f"Certificate also covers {plural(len(related), 'other domain')}",
            "Often reveals related brands or infrastructure: " + ", ".join(related[:15]),
        ))

    findings.append(Finding("info", f"Issued by {data.get('issuer')}", f"Valid for {days_left} more days."))
    return findings
