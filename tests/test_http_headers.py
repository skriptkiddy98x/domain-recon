from domain_recon.modules.http_headers import (
    analyze_security_headers,
    detect_technologies,
    extract_title,
    parse_robots_disallowed,
)

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "server": "nginx",
}


def test_well_configured_site_has_no_findings():
    assert analyze_security_headers(GOOD_HEADERS, is_https=True) == []


def test_missing_headers_are_reported():
    titles = [finding.title for finding in analyze_security_headers({}, is_https=True)]
    assert "Missing HSTS header" in titles
    assert "Missing Content-Security-Policy" in titles
    assert "Page can be embedded in other sites (clickjacking)" in titles


def test_hsts_is_ignored_on_plain_http():
    titles = [finding.title for finding in analyze_security_headers({}, is_https=False)]
    assert "Missing HSTS header" not in titles


def test_x_frame_options_prevents_clickjacking_finding():
    headers = {**GOOD_HEADERS, "content-security-policy": "default-src 'self'", "x-frame-options": "DENY"}
    assert analyze_security_headers(headers, is_https=True) == []


def test_version_disclosure():
    headers = {**GOOD_HEADERS, "server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"}
    findings = analyze_security_headers(headers, is_https=True)
    assert len(findings) == 2
    assert all(finding.severity == "low" for finding in findings)


def test_detect_technologies_from_headers_cookies_and_html():
    html = '<html><head><meta name="generator" content="WordPress 6.6.1"></head></html>'
    found = detect_technologies({"server": "cloudflare", "cf-ray": "abc"}, ["PHPSESSID"], html)
    assert found == ["Cloudflare", "PHP", "WordPress 6.6.1"]


def test_parse_robots_disallowed():
    robots = "User-agent: *\nDisallow: /admin/  # secret\nDisallow: /\nDisallow:\nAllow: /public\nDisallow: /admin/"
    assert parse_robots_disallowed(robots) == ["/admin/"]


def test_extract_title():
    assert extract_title("<html><title>\n  Example  Domain \n</title></html>") == "Example Domain"
    assert extract_title("<html></html>") is None
