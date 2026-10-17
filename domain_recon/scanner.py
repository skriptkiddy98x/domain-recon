"""Runs the selected modules in parallel and collects their results into one report."""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from types import ModuleType

from domain_recon import __version__
from domain_recon.models import ModuleResult, ScanContext, ScanReport
from domain_recon.modules import ALL_MODULES


def run_scan(
    ctx: ScanContext,
    module_names: list[str],
    on_module_done: Callable[[ModuleResult], None] | None = None,
) -> ScanReport:
    started_at = utc_now()
    results: dict[str, ModuleResult] = {}

    with ThreadPoolExecutor(max_workers=len(module_names)) as pool:
        futures = {pool.submit(run_module, ALL_MODULES[name], ctx): name for name in module_names}
        for future in as_completed(futures):
            result = future.result()
            results[futures[future]] = result
            if on_module_done:
                on_module_done(result)

    return ScanReport(
        domain=ctx.domain,
        started_at=started_at,
        finished_at=utc_now(),
        tool_version=__version__,
        results=[results[name] for name in module_names],  # keep report order stable
    )


def run_module(module: ModuleType, ctx: ScanContext) -> ModuleResult:
    """Run one module. A failing data source must never stop the rest of the scan."""
    start = time.perf_counter()
    try:
        result = module.run(ctx)
    except Exception as exc:  # noqa: BLE001 - we report the error instead of crashing
        result = ModuleResult(module.NAME, module.TITLE, module.SOURCE, error=f"{type(exc).__name__}: {exc}")
    result.duration_seconds = round(time.perf_counter() - start, 2)
    return result


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
