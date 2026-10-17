import json
from types import SimpleNamespace

import pytest

from domain_recon import cli
from domain_recon.cli import select_modules
from domain_recon.models import Finding, ModuleResult, ScanReport
from domain_recon.modules import ALL_MODULES
from domain_recon.report import (
    humanize_key,
    overview_rows,
    render_html,
    render_json,
    render_overview_html,
    summarize_report,
)
from domain_recon.scanner import run_module


def make_report(domain: str = "example.com", high: int = 1) -> ScanReport:
    findings = [Finding("info", "Info item")] + [Finding("high", "No DMARC record", "detail")] * high
    return ScanReport(
        domain=domain,
        started_at="2026-10-17T08:00:00+00:00",
        finished_at="2026-10-17T08:01:00+00:00",
        tool_version="0.1.0",
        results=[
            ModuleResult(
                "email", "Email security", "DNS",
                data={
                    "spoofing_risk": "high",
                    "spf": ["v=spf1 -all"],
                    "hosts": [{"name": "<script>alert(1)</script>", "live": True}],
                },
                findings=findings,
            ),
            ModuleResult("wayback", "Wayback", "CDX", error="ReadTimeout: too slow"),
        ],
    )


# --- CLI helpers -----------------------------------------------------------------------

def test_select_modules():
    assert select_modules(None, None) == list(ALL_MODULES)
    assert select_modules("email,dns", None) == ["dns", "email"]
    assert "typosquat" not in select_modules(None, "typosquat")
    with pytest.raises(ValueError):
        select_modules("nope", None)


def test_every_module_follows_the_interface():
    for name, module in ALL_MODULES.items():
        assert module.NAME == name
        assert module.TITLE and module.SOURCE
        assert callable(module.run)


def test_run_module_turns_exceptions_into_errors():
    def broken_run(ctx):
        raise TimeoutError("source did not answer")

    module = SimpleNamespace(NAME="broken", TITLE="Broken", SOURCE="test", run=broken_run)
    result = run_module(module, ctx=None)
    assert result.error == "TimeoutError: source did not answer"


# --- Whole CLI flow, with the network replaced by fakes --------------------------------

@pytest.fixture
def fake_network(monkeypatch):
    monkeypatch.setattr(cli, "domain_exists", lambda resolver, domain: domain != "missing.com")
    monkeypatch.setattr(cli, "run_scan", lambda ctx, modules, on_module_done=None: make_report(ctx.domain))


def test_main_scans_every_domain_and_links_them_in_an_overview(tmp_path, fake_network):
    domain_file = tmp_path / "domains.txt"
    domain_file.write_text("# targets\nexample.org, missing.com\nhttps://shop.example.net/page\n", encoding="utf-8")
    out = tmp_path / "out"

    assert cli.main(["example.com", "-i", str(domain_file), "-o", str(out)]) == 0

    assert sorted(path.name for path in out.iterdir()) == [
        "example.com.html", "example.com.json",
        "example.net.html", "example.net.json",
        "example.org.html", "example.org.json",
        "index.html", "summary.json",
    ]
    overview = (out / "index.html").read_text(encoding="utf-8")
    for domain in ("example.com", "example.net", "example.org"):
        assert f'href="{domain}.html"' in overview
    assert "missing.com" not in overview
    assert 'href="index.html"' in (out / "example.org.html").read_text(encoding="utf-8")
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert [row["domain"] for row in summary["domains"]] == ["example.com", "example.net", "example.org"]


def test_main_with_one_domain_writes_no_overview(tmp_path, fake_network):
    out = tmp_path / "out"
    assert cli.main(["https://www.example.com/", "-o", str(out)]) == 0
    assert sorted(path.name for path in out.iterdir()) == ["example.com.html", "example.com.json"]
    assert "All scanned domains" not in (out / "example.com.html").read_text(encoding="utf-8")


def test_main_fails_when_nothing_can_be_scanned(tmp_path, fake_network):
    assert cli.main(["missing.com", "-o", str(tmp_path)]) == 2
    with pytest.raises(SystemExit):
        cli.main(["not a domain", "-o", str(tmp_path)])


# --- Reports ---------------------------------------------------------------------------

def test_findings_are_sorted_and_counted():
    report = make_report()
    assert [finding.severity for _, finding in report.sorted_findings()] == ["high", "info"]
    assert report.severity_counts() == {"high": 1, "medium": 0, "low": 0, "info": 1}


def test_render_html_escapes_data_and_shows_errors():
    html = render_html(make_report())
    assert "example.com" in html
    assert "No DMARC record" in html
    assert "ReadTimeout: too slow" in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_html_links_back_to_overview_only_in_a_batch():
    assert 'href="index.html"' in render_html(make_report(), overview_href="index.html")
    assert 'href="index.html"' not in render_html(make_report())


def test_summarize_report():
    row = summarize_report(make_report())
    assert row["domain"] == "example.com"
    assert row["high"] == 1
    assert row["email_spoofing_risk"] == "high"
    assert row["top_finding"] == "No DMARC record"
    assert row["failed_modules"] == ["wayback"]


def test_overview_puts_most_serious_domains_first():
    reports = [make_report("calm.com", high=0), make_report("worst.com", high=3), make_report("bad.com", high=1)]
    assert [row["domain"] for row in overview_rows(reports)] == ["worst.com", "bad.com", "calm.com"]


def test_render_overview_html_links_every_domain():
    html = render_overview_html([make_report("a.com"), make_report("b.org")])
    assert "2 domains scanned" in html
    assert 'href="a.com.html"' in html
    assert 'href="https://b.org"' in html


def test_humanize_key():
    assert humanize_key("days_left") == "Days left"
    assert humanize_key("dkim_selectors_found") == "DKIM selectors found"
    assert humanize_key("mx") == "MX"
    assert humanize_key("AAAA") == "AAAA"


def test_render_json_round_trips():
    data = json.loads(render_json(make_report()))
    assert data["domain"] == "example.com"
    assert data["results"][0]["findings"][1]["title"] == "No DMARC record"
