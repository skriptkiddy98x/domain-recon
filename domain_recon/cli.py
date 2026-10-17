"""Command-line interface.

    domain-recon example.com
    domain-recon example.com firma.sk https://shop.example.net/page
    domain-recon -i domains.txt --open
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from domain_recon import __version__
from domain_recon.models import ModuleResult, ScanContext, ScanReport, plural
from domain_recon.modules import ALL_MODULES
from domain_recon.net import domain_exists, make_http_session, make_resolver
from domain_recon.report import OVERVIEW_HTML, overview_rows, write_overview, write_reports
from domain_recon.scanner import run_scan
from domain_recon.targets import prepare_targets, read_domain_file, split_domain_list


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-recon",
        description="Passive OSINT reconnaissance for one or many domains. Writes an HTML and a JSON "
        "report per domain, plus an overview page with links to all reports when you scan several.",
        epilog="Only scan domains you own or are authorised to assess.",
    )
    parser.add_argument("domains", nargs="*", metavar="domain", help="domains or URLs, e.g. example.com firma.sk")
    parser.add_argument("-i", "--input-file", type=Path, help="text file with domains (one per line, or separated "
                        "by spaces or commas; '#' starts a comment)")
    parser.add_argument("-m", "--modules", help="comma-separated modules to run (default: all)")
    parser.add_argument("-s", "--skip", help="comma-separated modules to skip")
    parser.add_argument("-o", "--output-dir", default="reports", help="where to write reports (default: reports)")
    parser.add_argument("-f", "--format", choices=("html", "json", "both"), default="both", help="report format")
    parser.add_argument("--open", action="store_true", help="open the report (or the overview) in your browser")
    parser.add_argument("--timeout", type=float, default=15.0, help="network timeout in seconds (default: 15)")
    parser.add_argument("--max-subdomains", type=int, default=200, help="subdomains to resolve (default: 200)")
    parser.add_argument("--max-lookalikes", type=int, default=300, help="lookalike domains to check (default: 300)")
    parser.add_argument("--list-modules", action="store_true", help="show available modules and exit")
    parser.add_argument("--version", action="version", version=f"domain-recon {__version__}")
    return parser


def select_modules(only: str | None, skip: str | None) -> list[str]:
    def parse_names(text: str | None) -> list[str]:
        names = [name.strip().lower() for name in (text or "").split(",") if name.strip()]
        unknown = [name for name in names if name not in ALL_MODULES]
        if unknown:
            raise ValueError(f"unknown module(s): {', '.join(unknown)}. Available: {', '.join(ALL_MODULES)}")
        return names

    selected = parse_names(only) or list(ALL_MODULES)
    skipped = set(parse_names(skip))
    modules = [name for name in ALL_MODULES if name in selected and name not in skipped]
    if not modules:
        raise ValueError("no modules left to run")
    return modules


def collect_entries(args: argparse.Namespace) -> list[str]:
    """Domains from the command line and the input file. If there are none, ask for them."""
    entries = split_domain_list("\n".join(args.domains))
    if args.input_file:
        entries += read_domain_file(args.input_file)
    if not entries and sys.stdin.isatty():
        try:
            entries = split_domain_list(input("  Domain(s) to scan, separated by spaces: "))
        except EOFError:
            pass
    return entries


def scan_domains(domains: list[str], module_names: list[str], args: argparse.Namespace) -> list[ScanReport]:
    """Scan the domains one after another and save each report as soon as it is ready."""
    http, resolver = make_http_session(), make_resolver()
    overview_href = OVERVIEW_HTML if len(domains) > 1 and args.format != "json" else None
    reports = []
    try:
        for position, domain in enumerate(domains, start=1):
            print(f"\n  [{position}/{len(domains)}] {domain}\n")
            if domain_exists(resolver, domain) is False:
                print(f"  skipped: {domain} does not exist in DNS")
                continue
            ctx = ScanContext(
                domain=domain,
                http=http,
                resolver=resolver,
                timeout=args.timeout,
                max_subdomains_to_resolve=args.max_subdomains,
                max_lookalikes_to_check=args.max_lookalikes,
            )
            report = run_scan(ctx, module_names, on_module_done=print_progress)
            paths = write_reports(report, Path(args.output_dir), args.format, overview_href)
            print_summary(report, paths)
            reports.append(report)
    except KeyboardInterrupt:
        print("\n  Interrupted. The reports that were already finished are kept.")
    return reports


# --- Terminal output -------------------------------------------------------------------

def print_module_list() -> None:
    for name, module in ALL_MODULES.items():
        print(f"  {name:<14} {module.TITLE}")
        print(f"  {'':<14} source: {module.SOURCE}")


def print_progress(result: ModuleResult) -> None:
    status = "error" if result.error else plural(len(result.findings), "finding")
    print(f"  [{'!' if result.error else '+'}] {result.title:<40} {result.duration_seconds:>6.1f}s  {status}")


def print_summary(report: ScanReport, paths: list[Path]) -> None:
    counts = report.severity_counts()
    print()
    print("  " + "   ".join(f"{severity.upper()}: {count}" for severity, count in counts.items()))
    for _, finding in report.sorted_findings():
        if finding.severity in ("high", "medium"):
            print(f"  - [{finding.severity.upper()}] {finding.title}")
    print()
    for path in paths:
        print(f"  Report: {file_link(path)}")


def print_overview(reports: list[ScanReport], paths: list[Path]) -> None:
    print("\n  " + "=" * 72)
    print(f"  {'DOMAIN':<34} {'HIGH':>5} {'MED':>5} {'LOW':>5} {'INFO':>5}   EMAIL SPOOFING")
    for row in overview_rows(reports):
        print(
            f"  {row['domain']:<34} {row['high']:>5} {row['medium']:>5} {row['low']:>5} {row['info']:>5}"
            f"   {row['email_spoofing_risk'] or '-'}"
        )
    print()
    for path in paths:
        print(f"  All domains: {file_link(path)}")


def file_link(path: Path) -> str:
    """A file:/// link that most terminals let you Ctrl+click."""
    return path.resolve().as_uri()


# --- Entry point -----------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        print_module_list()
        return 0

    try:
        module_names = select_modules(args.modules, args.skip)
        entries = collect_entries(args)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    domains, notes = prepare_targets(entries)
    for note in notes:
        print(f"  note: {note}")
    if not domains:
        parser.error("no valid domain to scan. Give one or more domains, or a file with -i")

    print(f"\n  domain-recon v{__version__}  |  {plural(len(domains), 'domain')}  |  "
          f"{plural(len(module_names), 'module')}")
    reports = scan_domains(domains, module_names, args)
    if not reports:
        print("\n  Nothing was scanned.", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir)
    page_to_open = output_dir / f"{reports[0].domain}.html"
    if len(domains) > 1:
        overview_paths = write_overview(reports, output_dir, args.format)
        print_overview(reports, overview_paths)
        page_to_open = output_dir / OVERVIEW_HTML

    if args.open and args.format != "json":
        webbrowser.open(file_link(page_to_open))
    return 0
