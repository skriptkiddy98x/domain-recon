"""Website: security headers, technology hints, robots.txt and security.txt.

Makes the same few requests a normal visitor's browser would make.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

import requests

from domain_recon.models import Finding, ModuleResult, ScanContext

NAME = "http"
TITLE = "Website & security headers"
SOURCE = "Homepage, /robots.txt and /.well-known/security.txt (like a normal visit)"

CONNECT_TIMEOUT = 6.0

# header -> (severity if missing, title, why it matters)
SECURITY_HEADERS = {
    "strict-transport-security": (
        "medium", "Missing HSTS header",
        "Browsers may first connect over plain HTTP, which allows downgrade attacks.",
    ),
    "content-security-policy": (
        "medium", "Missing Content-Security-Policy",
        "No browser-level limit on where scripts can load from (XSS mitigation).",
    ),
    "x-content-type-options": (
        "low", "Missing X-Content-Type-Options",
        "Browsers may guess ('sniff') content types, which can turn uploads into scripts.",
    ),
    "referrer-policy": (
        "low", "Missing Referrer-Policy",
        "Full URLs, including tokens in them, may leak to other sites via the Referer header.",
    ),
}
VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

HEADER_TECHNOLOGIES = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-vercel-id": "Vercel",
    "x-nf-request-id": "Netlify",
    "x-github-request-id": "GitHub Pages",
    "x-shopify-stage": "Shopify",
    "x-wix-request-id": "Wix",
    "x-drupal-cache": "Drupal",
    "x-akamai-transformed": "Akamai",
}
COOKIE_TECHNOLOGIES = {
    "phpsessid": "PHP",
    "jsessionid": "Java",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "wordpress_": "WordPress",
    "wp-settings": "WordPress",
    "_shopify": "Shopify",
    "django": "Django",
    "csrftoken": "Django",
}
GENERATOR_PATTERN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def run(ctx: ScanContext) -> ModuleResult:
    result = ModuleResult(NAME, TITLE, SOURCE)
    response = fetch_homepage(ctx.domain, ctx.http, ctx.timeout)
    headers = {key.lower(): value for key, value in response.headers.items()}
    is_https = response.url.startswith("https://")
    final_url = urlsplit(response.url)
    base_url = f"{final_url.scheme}://{final_url.netloc}"

    robots_paths = fetch_robots_disallowed(base_url, ctx.http, ctx.timeout)
    has_security_txt = fetch_security_txt(base_url, ctx.http, ctx.timeout)
    redirects_to_https = check_https_redirect(ctx.domain, ctx.http, ctx.timeout)

    result.data = {
        "final_url": response.url,
        "status_code": response.status_code,
        "redirect_chain": [r.url for r in response.history],
        "page_title": extract_title(response.text),
        "http_redirects_to_https": redirects_to_https,
        "technologies": detect_technologies(headers, response.cookies.keys(), response.text),
        "security_headers": {name: headers.get(name) for name in [*SECURITY_HEADERS, "x-frame-options"]},
        "security_txt": has_security_txt,
        "robots_disallowed_paths": robots_paths,
        "all_headers": headers,
    }

    findings = analyze_security_headers(headers, is_https)
    if not is_https:
        findings.insert(0, Finding("high", "Website is not served over HTTPS", response.url))
    elif redirects_to_https is False:
        findings.append(Finding(
            "medium",
            "HTTP does not redirect to HTTPS",
            f"http://{ctx.domain}/ stays on plain HTTP.",
        ))
    if not has_security_txt:
        findings.append(Finding(
            "info",
            "No security.txt",
            "There is no published way to report vulnerabilities (RFC 9116).",
        ))
    if robots_paths:
        findings.append(Finding(
            "info",
            f"robots.txt hides {len(robots_paths)} paths from search engines",
            ", ".join(robots_paths[:10]) + (" ..." if len(robots_paths) > 10 else ""),
        ))
    result.findings = findings
    return result


def fetch_homepage(domain: str, http: requests.Session, timeout: float) -> requests.Response:
    """Try HTTPS first, then plain HTTP, each with and without 'www.'."""
    last_error: requests.RequestException | None = None
    for url in (f"https://{domain}/", f"https://www.{domain}/", f"http://{domain}/", f"http://www.{domain}/"):
        try:
            return http.get(url, timeout=(CONNECT_TIMEOUT, timeout), allow_redirects=True)
        except requests.RequestException as exc:
            last_error = exc
    raise last_error


def check_https_redirect(domain: str, http: requests.Session, timeout: float) -> bool | None:
    try:
        response = http.get(f"http://{domain}/", timeout=(CONNECT_TIMEOUT, timeout), allow_redirects=True)
    except requests.RequestException:
        return None
    return response.url.startswith("https://")


def fetch_robots_disallowed(base_url: str, http: requests.Session, timeout: float) -> list[str]:
    try:
        response = http.get(f"{base_url}/robots.txt", timeout=(CONNECT_TIMEOUT, timeout))
    except requests.RequestException:
        return []
    if response.status_code != 200 or "<html" in response.text[:500].lower():
        return []
    return parse_robots_disallowed(response.text)


def parse_robots_disallowed(robots_txt: str) -> list[str]:
    paths = []
    for line in robots_txt.splitlines():
        key, _, value = line.partition(":")
        value = value.split("#")[0].strip()
        if key.strip().lower() == "disallow" and value and value != "/" and value not in paths:
            paths.append(value)
    return paths[:100]


def fetch_security_txt(base_url: str, http: requests.Session, timeout: float) -> bool:
    try:
        response = http.get(f"{base_url}/.well-known/security.txt", timeout=(CONNECT_TIMEOUT, timeout))
    except requests.RequestException:
        return False
    return response.status_code == 200 and "contact:" in response.text.lower()


def extract_title(html: str) -> str | None:
    match = TITLE_PATTERN.search(html[:200_000])
    return " ".join(match.group(1).split())[:200] if match else None


def detect_technologies(headers: Mapping[str, str], cookie_names, html: str) -> list[str]:
    """Best-effort hints about the software behind the site."""
    found = [technology for header, technology in HEADER_TECHNOLOGIES.items() if header in headers]
    for cookie in cookie_names:
        for prefix, technology in COOKIE_TECHNOLOGIES.items():
            if cookie.lower().startswith(prefix):
                found.append(technology)
    if generator := GENERATOR_PATTERN.search(html[:200_000]):
        found.append(generator.group(1))
    found += [headers[header] for header in ("server", "x-powered-by", "x-generator") if headers.get(header)]

    unique = {}  # case-insensitive de-duplication: 'cloudflare' header vs 'Cloudflare' hint
    for technology in found:
        unique.setdefault(technology.lower(), technology)
    return sorted(unique.values(), key=str.lower)


def analyze_security_headers(headers: Mapping[str, str], is_https: bool) -> list[Finding]:
    """Check for missing security headers. Header names must be lowercase."""
    findings = []
    for header, (severity, title, detail) in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not is_https:
            continue  # HSTS only means something on HTTPS responses
        if header not in headers:
            findings.append(Finding(severity, title, detail))

    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        findings.append(Finding(
            "low",
            "Page can be embedded in other sites (clickjacking)",
            "Neither X-Frame-Options nor CSP frame-ancestors is set.",
        ))

    for header in VERSION_HEADERS:
        value = headers.get(header, "")
        if re.search(r"\d", value):
            findings.append(Finding(
                "low",
                f"Software version disclosed in '{header}' header",
                f"{header}: {value} (helps attackers look up known vulnerabilities)",
            ))
    return findings
