"""Data structures shared by every recon module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

import dns.resolver
import requests

Severity = Literal["high", "medium", "low", "info"]

SEVERITY_ORDER: dict[str, int] = {"high": 0, "medium": 1, "low": 2, "info": 3}


def plural(count: int, noun: str) -> str:
    """plural(1, 'domain') -> '1 domain', plural(3, 'domain') -> '3 domains'"""
    return f"{count} {noun}{'' if count == 1 else 's'}"


@dataclass
class Finding:
    """One observation worth a human's attention."""

    severity: Severity
    title: str
    detail: str = ""


@dataclass
class ModuleResult:
    """What a recon module returns: the raw data it collected plus interpreted findings."""

    module: str
    title: str
    source: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0


@dataclass
class ScanContext:
    """Everything a module needs to do its job. Shared by all modules in one scan."""

    domain: str
    http: requests.Session
    resolver: dns.resolver.Resolver
    timeout: float = 15.0
    max_subdomains_to_resolve: int = 200
    max_lookalikes_to_check: int = 300


@dataclass
class ScanReport:
    """The complete result of one scan, ready to be rendered as HTML or JSON."""

    domain: str
    started_at: str
    finished_at: str
    tool_version: str
    results: list[ModuleResult]

    def sorted_findings(self) -> list[tuple[ModuleResult, Finding]]:
        """All findings from all modules, most severe first."""
        pairs = [(result, finding) for result in self.results for finding in result.findings]
        return sorted(pairs, key=lambda pair: SEVERITY_ORDER[pair[1].severity])

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for result in self.results:
            for finding in result.findings:
                counts[finding.severity] += 1
        return counts
