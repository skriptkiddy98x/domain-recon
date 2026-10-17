"""Recon modules. Each module exposes NAME, TITLE, SOURCE and run(ctx) -> ModuleResult."""

from domain_recon.modules import (
    dns_records,
    email_security,
    hosting,
    http_headers,
    registration,
    subdomains,
    tls_cert,
    typosquat,
    wayback,
)

# Order here is the order of sections in the report.
ALL_MODULES = {
    module.NAME: module
    for module in (
        dns_records,
        registration,
        hosting,
        email_security,
        tls_cert,
        http_headers,
        subdomains,
        wayback,
        typosquat,
    )
}
