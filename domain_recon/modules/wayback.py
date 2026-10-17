"""Archived URLs from the Wayback Machine.

Old snapshots often remember files that were removed from the live site: backups,
config files, admin panels or forgotten API endpoints.
"""

from __future__ import annotations

import re
from collections import Counter

import requests

from domain_recon.models import Finding, ModuleResult, ScanContext

NAME = "wayback"
TITLE = "Archived URLs (Wayback Machine)"
SOURCE = "Internet Archive CDX API"

CDX_URL = "https://web.archive.org/cdx/search/cdx"
MAX_URLS = 5000

INTERESTING_URL_PATTERN = re.compile(
    r"(\.(env|bak|old|backup|sql|db|sqlite|zip|tar|gz|tgz|7z|rar|log|conf|cfg|ini|yml|yaml|"
    r"key|pem|p12|swp|git)(\?|$))"
    r"|(/(admin|administrator|wp-admin|phpmyadmin|backup|backups|config|debug|staging|"
    r"internal|private|graphql|swagger|api-docs|\.git|\.svn|\.env)(/|\?|$))",
    re.IGNORECASE,
)
TEMPLATE_MARKERS = ("$", "{", "}", "%7b", "%7d", "%22", "%25")


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    captures = fetch_archived_urls(ctx.domain, ctx.http, max(ctx.timeout, 60))
    timestamps = sorted(capture["timestamp"] for capture in captures)
    interesting = find_interesting_urls(capture["original"] for capture in captures)

    result.data = {
        "unique_urls": len(captures),
        "limit_reached": len(captures) >= MAX_URLS,
        "first_capture": format_timestamp(timestamps[0]) if timestamps else None,
        "top_file_types": count_file_types(capture.get("mimetype", "") for capture in captures),
        "interesting_urls": interesting,
    }

    findings = []
    if captures:
        findings.append(Finding(
            "info",
            f"{len(captures)}{'+' if result.data['limit_reached'] else ''} unique URLs archived",
            f"First capture: {result.data['first_capture']}.",
        ))
    if interesting:
        findings.append(Finding(
            "medium",
            f"Archived URLs with potentially sensitive paths ({len(interesting)})",
            "They may no longer be live, but can reveal backups, configs or admin panels: "
            + ", ".join(interesting[:8]) + (" ..." if len(interesting) > 8 else ""),
        ))
    result.findings = findings
    return result


def fetch_archived_urls(domain: str, http: requests.Session, timeout: float) -> list[dict]:
    """One row per unique URL (including subdomains), oldest capture first."""
    params = {
        "url": domain,
        "matchType": "domain",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(MAX_URLS),
    }
    response = http.get(CDX_URL, params=params, timeout=timeout)
    response.raise_for_status()
    rows = response.json() if response.text.strip() else []
    if not rows:
        return []
    header, *entries = rows
    return [dict(zip(header, row, strict=False)) for row in entries]


def find_interesting_urls(urls) -> list[str]:
    interesting = []
    for url in urls:
        if looks_like_real_url(url) and INTERESTING_URL_PATTERN.search(url) and url not in interesting:
            interesting.append(url)
    return interesting[:200]


def looks_like_real_url(url: str) -> bool:
    """The archive also holds junk: unexpanded templates ($version) and glued-together links."""
    after_scheme = url.lower()[8:]
    return (
        len(url) <= 300
        and "://" not in after_scheme
        and not any(marker in after_scheme for marker in TEMPLATE_MARKERS)
    )


def count_file_types(mimetypes) -> dict[str, int]:
    return dict(Counter(mimetype for mimetype in mimetypes if mimetype).most_common(5))


def format_timestamp(timestamp: str) -> str:
    """'20190314123456' -> '2019-03-14'"""
    return f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
