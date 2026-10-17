from domain_recon.modules.email_security import (
    analyze_dkim,
    analyze_dmarc,
    analyze_spf,
    assess_spoofing_risk,
    detect_email_providers,
    is_active_dkim_key,
    parse_spf,
    parse_tags,
)


def titles(findings):
    return [finding.title for finding in findings]


def test_parse_spf_reads_policy_includes_and_lookups():
    spf = parse_spf("v=spf1 include:_spf.google.com include:sendgrid.net mx a:mail.example.com -all")
    assert spf["all"] == "-all"
    assert spf["includes"] == ["_spf.google.com", "sendgrid.net"]
    assert spf["dns_lookups"] == 4


def test_parse_spf_treats_bare_all_as_pass():
    assert parse_spf("v=spf1 all")["all"] == "+all"


def test_parse_spf_reads_redirect():
    spf = parse_spf("v=spf1 redirect=_spf.example.net")
    assert spf["redirect"] == "_spf.example.net"
    assert spf["all"] is None


def test_missing_spf_is_high():
    findings = analyze_spf([])
    assert findings[0].severity == "high"


def test_multiple_spf_records_are_broken():
    findings = analyze_spf(["v=spf1 -all", "v=spf1 ~all"])
    assert titles(findings) == ["Multiple SPF records"]


def test_strict_spf_has_no_findings():
    assert analyze_spf(["v=spf1 include:_spf.google.com -all"]) == []


def test_softfail_spf_is_low():
    findings = analyze_spf(["v=spf1 include:_spf.google.com ~all"])
    assert [finding.severity for finding in findings] == ["low"]


def test_plus_all_is_high():
    assert analyze_spf(["v=spf1 +all"])[0].severity == "high"


def test_spf_redirect_without_all_is_fine():
    assert analyze_spf(["v=spf1 redirect=_spf.example.net"]) == []


def test_too_many_spf_lookups():
    record = "v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(11)) + " -all"
    assert any("DNS lookups" in title for title in titles(analyze_spf([record])))


def test_parse_tags_reads_dmarc_record():
    tags = parse_tags("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100")
    assert tags == {"v": "DMARC1", "p": "reject", "rua": "mailto:dmarc@example.com", "pct": "100"}


def test_missing_dmarc_is_high():
    assert analyze_dmarc([])[0].severity == "high"


def test_dmarc_reject_with_reports_is_clean():
    assert analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"]) == []


def test_dmarc_none_is_medium():
    findings = analyze_dmarc(["v=DMARC1; p=none; rua=mailto:d@example.com"])
    assert [finding.severity for finding in findings] == ["medium"]


def test_dmarc_partial_pct_and_missing_rua():
    found = titles(analyze_dmarc(["v=DMARC1; p=reject; pct=25"]))
    assert "DMARC applies to only 25% of mail" in found
    assert "No DMARC aggregate reports (rua)" in found


def test_spoofing_risk_levels():
    assert assess_spoofing_risk([], []) == "high"
    assert assess_spoofing_risk(["v=spf1 ~all"], ["v=DMARC1; p=none"]) == "high"
    assert assess_spoofing_risk(["v=spf1 -all"], ["v=DMARC1; p=none"]) == "medium"
    assert assess_spoofing_risk(["v=spf1 ~all"], ["v=DMARC1; p=reject"]) == "low"


def test_revoked_dkim_key_does_not_count():
    assert is_active_dkim_key("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC")
    assert not is_active_dkim_key("v=DKIM1; p=")


def test_dkim_missing_only_reported_for_domains_with_mail():
    assert analyze_dkim([], has_mx=True)[0].severity == "info"
    assert analyze_dkim([], has_mx=False) == []
    assert analyze_dkim(["google"], has_mx=True) == []


def test_detect_email_providers():
    providers = detect_email_providers(
        ["1 aspmx.l.google.com."],
        ["v=spf1 include:_spf.google.com include:sendgrid.net -all"],
    )
    assert providers == ["Google Workspace", "SendGrid"]
