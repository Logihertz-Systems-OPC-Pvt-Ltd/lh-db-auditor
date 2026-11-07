# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        src.lh_db_auditor.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-db-auditor.

Implements CLI commands:
- lh-db scan <path> [--format table|json|sarif] [--output <path>]
                    [--min-severity <level>] [--fail-on <level>]
- lh-db rules
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from lh_db_auditor.exporters import (
    OutputFormat,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_db_auditor.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
    ScanTargetResult,
)
from lh_db_auditor.mysql_scanner import scan_mysql_conf
from lh_db_auditor.nosql_scanner import scan_mongodb_conf, scan_redis_conf
from lh_db_auditor.postgres_scanner import scan_pg_hba, scan_postgresql_conf

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-db",
    help=(
        "Enterprise database security posture auditor for PostgreSQL, MySQL, Redis, and MongoDB.\n"
        "Developed by Logihertz Systems (OPC) Private Limited."
    ),
    no_args_is_help=True,
    rich_markup_mode=None,
)
console = Console()


def _detect_and_scan(path: Path) -> ScanTargetResult:
    """Identify database engine and scan target file."""
    name_lower = path.name.lower()

    if "pg_hba" in name_lower:
        return scan_pg_hba(path)
    if "postgres" in name_lower:
        return scan_postgresql_conf(path)
    if "my.cnf" in name_lower or "mysqld" in name_lower or name_lower.endswith(".cnf"):
        return scan_mysql_conf(path)
    if "redis" in name_lower:
        return scan_redis_conf(path)
    if "mongod" in name_lower or "mongodb" in name_lower:
        return scan_mongodb_conf(path)

    # Content-based detection for generic filenames (e.g. database.conf, test.yaml)
    try:
        sample = path.read_text(encoding="utf-8")[:2048]
    except Exception as e:
        return ScanTargetResult(
            target=str(path),
            error_message=f"Failed to read file '{path}': {e}",
        )

    if "[mysqld]" in sample or "[client]" in sample or "[mysql]" in sample:
        return scan_mysql_conf(path)
    if "bindip" in sample.lower() or "auditlog:" in sample or "systemlog:" in sample:
        return scan_mongodb_conf(path)
    if any(
        sample.startswith(prefix)
        for prefix in ("local ", "host ", "hostssl ", "hostnossl ", "# TYPE")
    ):
        return scan_pg_hba(path)
    if "requirepass" in sample.lower() or "protected-mode" in sample.lower():
        return scan_redis_conf(path)

    # Default to postgresql.conf scanner
    return scan_postgresql_conf(path)


def _discover_files(target_path: Path) -> list[Path]:
    """Discover all candidate database configuration files."""
    if target_path.is_file():
        return [target_path]

    found: list[Path] = []
    patterns = (
        "*.conf",
        "*.cnf",
        "*.yaml",
        "*.yml",
        "pg_hba.conf",
        "postgresql.conf",
        "my.cnf",
        "mysqld.cnf",
        "redis.conf",
        "mongod.conf",
    )
    for pat in patterns:
        for p in target_path.rglob(pat):
            if any(part.startswith(".") for part in p.parts):
                continue
            found.append(p)
    return sorted(set(found))


def _discover_and_scan(target_path: Path) -> list[ScanTargetResult]:
    """Discover candidate configuration files and execute security audits."""
    results: list[ScanTargetResult] = []

    files = _discover_files(target_path)
    if not files:
        results.append(
            ScanTargetResult(
                target=str(target_path),
                findings=[],
                error_message=f"No database configuration files found in {target_path}",
            )
        )
        return results

    for f in files:
        results.append(_detect_and_scan(f))

    return results


def _output_report(
    report: AuditReport,
    fmt: OutputFormat,
    output_path: Path | None,
) -> None:
    """Format and write or print the audit report according to format and destination."""
    report.compute_summary()

    if fmt == OutputFormat.JSON:
        rendered = export_json(report)
    elif fmt == OutputFormat.SARIF:
        rendered = export_sarif(report)
    else:
        if output_path:
            file_console = Console(record=True, width=120, color_system=None)
            render_table_report(report, console=file_console)
            rendered = file_console.export_text()
        else:
            render_table_report(report, console=console)
            rendered = ""

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Report successfully written to {output_path}[/bold green]")
    elif rendered:
        print(rendered)


@app.command(name="scan")
def scan(
    path: Annotated[
        str,
        typer.Argument(
            help="Path to database configuration file (.conf, .cnf, .yaml) or directory."
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: table, json, or sarif."),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Path to write output report file."),
    ] = None,
    min_severity: Annotated[
        FindingSeverity | None,
        typer.Option("--min-severity", "-s", help="Filter findings below this severity."),
    ] = None,
    fail_on: Annotated[
        FindingSeverity | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for failure exit (CRITICAL, HIGH, MEDIUM, LOW).",
        ),
    ] = FindingSeverity.HIGH,
) -> None:
    """Scan database configurations for security misconfigurations and hardening risks."""
    target_path = Path(path)
    if not target_path.exists():
        console.print(f"[bold red]Error: Target path '{path}' does not exist.[/bold red]")
        raise typer.Exit(code=2)

    results = _discover_and_scan(target_path)

    report = AuditReport(
        report_type="database_security_audit",
        generated_at=datetime.now(UTC),
        parameters={
            "path": path,
            "format": format.value,
            "min_severity": min_severity.value if min_severity else None,
            "fail_on": fail_on.value if fail_on else None,
        },
        results=results,
    )

    if min_severity is not None:
        report.filter_min_severity(min_severity)

    _output_report(report, format, output)

    if report.has_failures(fail_on):
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command(name="rules")
def rules() -> None:
    """List all supported LH-DB database security detection rules."""
    table = Table(
        title="LH-DB Database Security Detection Rules",
        border_style="blue",
    )
    table.add_column("Rule ID", style="bold magenta", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Category", style="cyan")
    table.add_column("Engines", style="bold yellow")
    table.add_column("Rule Title", style="bold white")
    table.add_column("Description")

    sev_styles = {
        FindingSeverity.CRITICAL: "bold white on red",
        FindingSeverity.HIGH: "bold red",
        FindingSeverity.MEDIUM: "bold yellow",
        FindingSeverity.LOW: "bold cyan",
    }

    for rule_id, rule_def in sorted(RULES_REGISTRY.items()):
        badge = Text(rule_def.severity.value, style=sev_styles.get(rule_def.severity, "bold"))
        engs = ", ".join(e.value for e in rule_def.engines)
        table.add_row(
            rule_id,
            badge,
            rule_def.category.value,
            engs,
            rule_def.title,
            rule_def.description,
        )

    console.print(table)


if __name__ == "__main__":
    app()
