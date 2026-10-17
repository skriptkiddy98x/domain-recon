from domain_recon.modules.typosquat import VALID_LABEL, analyze_lookalikes, generate_lookalikes, split_domain


def test_split_domain_keeps_multi_part_suffix():
    assert split_domain("example.co.uk") == ("example", "co.uk")


def test_generates_common_typo_techniques():
    candidates = generate_lookalikes("example.com")
    assert candidates["exmple.com"] == "missing letter"
    assert candidates["exmaple.com"] == "swapped letters"
    assert candidates["exaample.com"] == "doubled letter"
    assert candidates["examp1e.com"] == "lookalike character"
    assert candidates["example.net"] == "different TLD"
    assert candidates["example-login.com"] == "added word"


def test_original_domain_is_never_a_candidate():
    assert "example.com" not in generate_lookalikes("example.com")


def test_all_candidates_are_valid_domain_names():
    for candidate in generate_lookalikes("my-shop.sk"):
        label = candidate.split(".")[0]
        assert VALID_LABEL.match(label), candidate


def test_most_abused_techniques_come_first():
    first = list(generate_lookalikes("example.com").values())[:5]
    assert set(first) == {"different TLD"}


def test_multi_char_homoglyph():
    assert "modem.com" in generate_lookalikes("rnodem.com")


def test_analyze_lookalikes_flags_mail_enabled_domains():
    registered = [
        {"domain": "exmple.com", "technique": "missing letter", "ips": ["192.0.2.1"], "can_receive_email": True},
        {"domain": "example.net", "technique": "different TLD", "ips": [], "can_receive_email": False},
    ]
    findings = analyze_lookalikes(registered)
    assert [finding.severity for finding in findings] == ["low", "medium"]
    assert "exmple.com" in findings[1].detail
    assert analyze_lookalikes([]) == []
