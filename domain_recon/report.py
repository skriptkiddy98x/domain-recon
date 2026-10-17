"""Turns scan results into self-contained HTML pages and JSON files.

One scan     -> <domain>.html + <domain>.json
Many domains -> the same per domain, plus index.html (overview with a link to every report)
                and summary.json
"""

from __future__ import annotations

import json
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from domain_recon import __version__
from domain_recon.models import SEVERITY_ORDER, ScanReport

OVERVIEW_HTML = "index.html"
OVERVIEW_JSON = "summary.json"


@lru_cache(maxsize=1)
def template_environment() -> Environment:
    env = Environment(
        loader=PackageLoader("domain_recon", "templates"),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["humanize"] = humanize_key
    return env


# --- One domain ------------------------------------------------------------------------

def render_html(report: ScanReport, overview_href: str | None = None) -> str:
    """overview_href adds a '← All scanned domains' link when the report is part of a batch."""
    template = template_environment().get_template("report.html")
    return template.render(report=report, overview_href=overview_href)


def render_json(report: ScanReport) -> str:
    return json.dumps(asdict(report), indent=2, ensure_ascii=False, default=str)


def write_reports(
    report: ScanReport,
    output_dir: Path,
    output_format: str,
    overview_href: str | None = None,
) -> list[Path]:
    """Write <domain>.html and/or <domain>.json and return the paths written."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    if output_format in ("html", "both"):
        path = output_dir / f"{report.domain}.html"
        path.write_text(render_html(report, overview_href), encoding="utf-8")
        written.append(path)
    if output_format in ("json", "both"):
        path = output_dir / f"{report.domain}.json"
        path.write_text(render_json(report), encoding="utf-8")
        written.append(path)
    return written


# --- Many domains ----------------------------------------------------------------------

def summarize_report(report: ScanReport) -> dict:
    """One row of the overview: finding counts and the headline for a domain."""
    findings = report.sorted_findings()
    email = next((result for result in report.results if result.module == "email" and not result.error), None)
    return {
        "domain": report.domain,
        **report.severity_counts(),
        "email_spoofing_risk": email.data.get("spoofing_risk") if email else None,
        "top_finding": findings[0][1].title if findings else None,
        "top_severity": findings[0][1].severity if findings else None,
        "failed_modules": [result.module for result in report.results if result.error],
    }


def overview_rows(reports: list[ScanReport]) -> list[dict]:
    """Rows for every scanned domain, the ones with the most serious findings first."""
    rows = [summarize_report(report) for report in reports]
    return sorted(rows, key=lambda row: (*(-row[severity] for severity in SEVERITY_ORDER), row["domain"]))


def render_overview_html(reports: list[ScanReport]) -> str:
    rows = overview_rows(reports)
    totals = {severity: sum(row[severity] for row in rows) for severity in SEVERITY_ORDER}
    return template_environment().get_template("overview.html").render(
        rows=rows,
        totals=totals,
        scanned_at=reports[0].started_at,
        tool_version=__version__,
    )


def render_overview_json(reports: list[ScanReport]) -> str:
    summary = {"tool_version": __version__, "scanned_at": reports[0].started_at, "domains": overview_rows(reports)}
    return json.dumps(summary, indent=2, ensure_ascii=False)


def write_overview(reports: list[ScanReport], output_dir: Path, output_format: str) -> list[Path]:
    """Write index.html and/or summary.json listing every scanned domain."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    if output_format in ("html", "both"):
        path = output_dir / OVERVIEW_HTML
        path.write_text(render_overview_html(reports), encoding="utf-8")
        written.append(path)
    if output_format in ("json", "both"):
        path = output_dir / OVERVIEW_JSON
        path.write_text(render_overview_json(reports), encoding="utf-8")
        written.append(path)
    return written


# --- Helpers ---------------------------------------------------------------------------

ACRONYMS = {
    "asn": "ASN", "caa": "CAA", "cname": "CNAME", "dkim": "DKIM", "dmarc": "DMARC", "dns": "DNS",
    "dnssec": "DNSSEC", "http": "HTTP", "https": "HTTPS", "ip": "IP", "ips": "IPs", "mx": "MX",
    "ns": "NS", "soa": "SOA", "spf": "SPF", "tls": "TLS", "txt": "TXT", "url": "URL", "urls": "URLs",
}


def humanize_key(key: str) -> str:
    """'days_left' -> 'Days left', 'dkim_selectors_found' -> 'DKIM selectors found'"""
    words = [ACRONYMS.get(word.lower(), word) for word in str(key).replace("_", " ").split()]
    text = " ".join(words)
    return text[:1].upper() + text[1:]
