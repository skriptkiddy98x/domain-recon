from domain_recon.modules.subdomains import analyze_subdomains, extract_subdomains, is_sensitive_name
from domain_recon.modules.wayback import count_file_types, find_interesting_urls, format_timestamp


def test_extract_subdomains_cleans_certificate_names():
    raw = [
        "*.example.com\nexample.com",
        "WWW.example.com",
        "dev.example.com.",
        "example.com.evil.net",
        "notexample.com",
    ]
    assert extract_subdomains(raw, "example.com") == ["dev.example.com", "www.example.com"]


def test_sensitive_names():
    assert is_sensitive_name("dev.example.com", "example.com")
    assert is_sensitive_name("vpn2.example.com", "example.com")
    assert is_sensitive_name("jenkins-old.eu.example.com", "example.com")
    assert not is_sensitive_name("www.example.com", "example.com")
    assert not is_sensitive_name("developer.example.com", "example.com")


def test_analyze_subdomains():
    hosts = [
        {"name": "dev.example.com", "ips": ["192.0.2.1"], "live": True, "sensitive": True, "dangling_cname": None},
        {"name": "shop.example.com", "ips": [], "live": False, "sensitive": False,
         "dangling_cname": "example-shop.herokuapp.com"},
    ]
    severities = [finding.severity for finding in analyze_subdomains(hosts, total_found=2)]
    assert severities == ["info", "high", "medium"]


def test_wildcard_dns_is_reported():
    findings = analyze_subdomains([], total_found=0, wildcard_ips={"192.0.2.10"})
    assert findings[1].title == "Wildcard DNS is enabled"
    assert "192.0.2.10" in findings[1].detail


def test_find_interesting_urls():
    urls = [
        "https://example.com/",
        "https://example.com/backup.zip",
        "https://example.com/wp-admin/",
        "https://example.com/.env",
        "https://example.com/blog/administration-tips",
        "https://example.com/backup.zip",
        "https://example.com/$pkgname-$pkgver.tar.gz",
        "https://example.com/%{name}/release.tar.gz",
        "http://example.com/%22tel:123http://example.com/admin/",
    ]
    assert find_interesting_urls(urls) == [
        "https://example.com/backup.zip",
        "https://example.com/wp-admin/",
        "https://example.com/.env",
    ]


def test_count_file_types_and_timestamps():
    assert count_file_types(["text/html", "text/html", "image/png", ""]) == {"text/html": 2, "image/png": 1}
    assert format_timestamp("20190314123456") == "2019-03-14"
