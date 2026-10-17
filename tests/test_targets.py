import pytest

from domain_recon.targets import (
    normalize_domain,
    normalize_host,
    prepare_targets,
    read_domain_file,
    registrable_domain,
    split_domain_list,
)


@pytest.mark.parametrize(("raw", "expected"), [
    ("example.com", "example.com"),
    ("  Example.COM.  ", "example.com"),
    ("https://www.example.com/path?q=1", "example.com"),
    ("http://user@example.com:8080", "example.com"),
    ("shop.example.co.uk", "shop.example.co.uk"),
    ("žilina.sk", "xn--ilina-tib.sk"),
])
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "exa mple.com", "-example.com", "example..com"])
def test_normalize_host_rejects_invalid(raw):
    with pytest.raises(ValueError):
        normalize_host(raw)


@pytest.mark.parametrize(("host", "expected"), [
    ("example.sk", "example.sk"),
    ("eshop.firma.sk", "firma.sk"),
    ("shop.example.co.uk", "example.co.uk"),
    ("name.github.io", "name.github.io"),
    ("github.io", "github.io"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize("host", ["foo.invalidtld", "co.uk", "10.0.0.12"])
def test_registrable_domain_rejects_non_domains(host):
    with pytest.raises(ValueError):
        registrable_domain(host)


def test_normalize_domain_combines_both_steps():
    assert normalize_domain("https://Blog.Example.co.uk/post/1") == "example.co.uk"


def test_split_domain_list_accepts_lines_spaces_commas_and_comments():
    text = "# my targets\nexample.com, firma.sk;test.org\n\n  another.net   # main site\n"
    assert split_domain_list(text) == ["example.com", "firma.sk", "test.org", "another.net"]


def test_read_domain_file_handles_utf8_bom(tmp_path):
    path = tmp_path / "domains.txt"
    path.write_text("example.com\nžilina.sk\n", encoding="utf-8-sig")
    assert read_domain_file(path) == ["example.com", "žilina.sk"]


def test_prepare_targets_deduplicates_and_explains():
    domains, notes = prepare_targets([
        "example.com",
        "https://www.example.com/",
        "shop.example.net",
        "not a domain",
        "firma.sk",
    ])
    assert domains == ["example.com", "example.net", "firma.sk"]
    assert notes == [
        "shop.example.net is a subdomain, scanning example.net instead",
        "skipped: 'not a domain' is not a valid domain name",
    ]
