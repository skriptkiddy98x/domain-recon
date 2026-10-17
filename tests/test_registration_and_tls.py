from datetime import datetime, timezone

from domain_recon.modules.registration import analyze_registration, parse_date, parse_rdap, parse_whois
from domain_recon.modules.tls_cert import analyze_certificate, parse_certificate

NOW = datetime(2026, 10, 17, tzinfo=timezone.utc)

RDAP_PAYLOAD = {
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    ],
    "entities": [{
        "roles": ["registrar"],
        "handle": "376",
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-IANA"]]],
    }],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    "status": ["client delete prohibited", "client transfer prohibited"],
    "secureDNS": {"delegationSigned": True},
}

WHOIS_TEXT = """
Domain:                       example.sk
Created:                      2004-03-12
Valid Until:                  2026-11-01
Updated:                      2025-10-20
Nameserver:                   ns1.example.net
Nameserver:                   NS2.example.net.
"""


def test_parse_rdap():
    info = parse_rdap(RDAP_PAYLOAD)
    assert info["registrar"] == "RESERVED-IANA"
    assert info["created"] == "1995-08-14T04:00:00Z"
    assert info["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert info["dnssec"] is True
    assert analyze_registration(info, NOW) == []


def test_parse_whois():
    info = parse_whois(WHOIS_TEXT)
    assert info["created"] == "2004-03-12"
    assert info["expires"] == "2026-11-01"
    assert info["nameservers"] == ["ns1.example.net", "ns2.example.net"]


def test_expiring_domain_is_high():
    findings = analyze_registration(parse_whois(WHOIS_TEXT), NOW)
    assert findings[0].severity == "high"
    assert "expires in 15 days" in findings[0].title


def test_new_domain_is_flagged():
    findings = analyze_registration({"created": "2026-09-30", "expires": "2027-09-30"}, NOW)
    assert [finding.severity for finding in findings] == ["medium"]


def test_parse_date_formats():
    assert parse_date("2026-07-24T04:00:00Z").year == 2026
    assert parse_date("2026-07-24").tzinfo is not None
    assert parse_date("2026-07-24 10:00:00").hour == 10
    assert parse_date("not a date") is None
    assert parse_date(None) is None


PEER_CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
    "notBefore": "Sep  1 00:00:00 2026 GMT",
    "notAfter": "Oct 27 00:00:00 2026 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"), ("DNS", "example-brand.net")),
}


def test_parse_certificate():
    cert = parse_certificate(PEER_CERT)
    assert cert["subject"] == "example.com"
    assert cert["issuer"] == "Let's Encrypt"
    assert cert["valid_until"].startswith("2026-10-27")
    assert cert["names_on_certificate"] == ["example.com", "*.example.com", "example-brand.net"]


def test_analyze_certificate_expiry_and_related_domains():
    data = {**parse_certificate(PEER_CERT), "protocol": "TLSv1.3", "days_left": 10}
    findings = analyze_certificate(data, "example.com")
    assert findings[0].severity == "high"
    assert any("example-brand.net" in finding.detail for finding in findings)
