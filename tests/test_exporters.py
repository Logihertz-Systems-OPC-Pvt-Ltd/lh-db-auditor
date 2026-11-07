# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report exporters (Table, JSON, SARIF v2.1.0)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from rich.console import Console

from lh_db_auditor.exporters import (
    OutputFormat,
    _get_severity_badge,
    export_json,
    export_sarif,
    render_table_report,
)
from lh_db_auditor.models import (
    AuditReport,
    ConfigCategory,
    DatabaseEngine,
    Finding,
    FindingSeverity,
    ScanTargetResult,
)


def _sample_report_with_findings() -> AuditReport:
    """Build mock AuditReport with findings across severity levels."""
    finding1 = Finding(
        rule_id="LH-DB-001",
        severity=FindingSeverity.CRITICAL,
        category=ConfigCategory.AUTHENTICATION,
        title="Insecure PostgreSQL pg_hba.conf Rule",
        message="pg_hba.conf permits trust authentication.",
        target="pg_hba.conf",
        engine=DatabaseEngine.POSTGRESQL,
        parameter="host 0.0.0.0/0",
        value="trust",
        line_number=10,
        remediation="Use scram-sha-256.",
    )
    finding2 = Finding(
        rule_id="LH-DB-002",
        severity=FindingSeverity.HIGH,
        category=ConfigCategory.NETWORK,
        title="Database Server Bound to All Interfaces",
        message="bind-address = 0.0.0.0",
        target="my.cnf",
        engine=DatabaseEngine.MYSQL,
        parameter="bind-address",
        value="0.0.0.0",
        line_number=15,
        remediation="Bind to localhost.",
    )
    res = ScanTargetResult(
        target="pg_hba.conf",
        engine=DatabaseEngine.POSTGRESQL,
        findings=[finding1, finding2],
        parameters_scanned=10,
    )
    return AuditReport(
        report_type="database_security_audit",
        generated_at=datetime.now(UTC),
        parameters={"path": "pg_hba.conf", "format": "table"},
        results=[res],
    )


def test_render_table_report_with_findings() -> None:
    """Verify terminal table rendering with findings."""
    report = _sample_report_with_findings()
    console = Console(record=True, width=120, color_system=None)
    render_table_report(report, console=console)
    text = console.export_text()

    assert "Database Security & Configuration Posture Audit" in text
    assert "Database Audit Executive Summary" in text
    assert "Database Engine Findings Breakdown" in text
    assert "LH-DB-001" in text
    assert "LH-DB-002" in text
    assert "CRITICAL" in text
    assert "HIGH" in text


def test_render_table_clean_report() -> None:
    """Verify terminal table rendering for clean compliant configurations."""
    report = AuditReport(
        report_type="database_security_audit",
        generated_at=datetime.now(UTC),
        parameters={"path": "clean.conf", "format": "table"},
        results=[
            ScanTargetResult(
                target="clean.conf",
                engine=DatabaseEngine.POSTGRESQL,
                findings=[],
                parameters_scanned=8,
            )
        ],
    )
    console = Console(record=True, width=120, color_system=None)
    render_table_report(report, console=console)
    text = console.export_text()

    assert "Clean Audit: Database configurations comply with hardening baselines." in text


def test_export_json_valid() -> None:
    """Verify structured JSON exporter output and schema integrity."""
    report = _sample_report_with_findings()
    raw_json = export_json(report)
    parsed = json.loads(raw_json)

    assert parsed["report_type"] == "database_security_audit"
    assert parsed["summary"]["total_findings"] == 2
    assert parsed["summary"]["critical"] == 1
    assert parsed["summary"]["high"] == 1
    assert len(parsed["results"]) == 1
    assert parsed["results"][0]["findings"][0]["rule_id"] == "LH-DB-001"


def test_export_sarif_valid_v210() -> None:
    """Verify OASIS SARIF v2.1.0 schema compliance and findings mapping."""
    report = _sample_report_with_findings()
    raw_sarif = export_sarif(report)
    parsed = json.loads(raw_sarif)

    assert parsed["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in parsed["$schema"]
    assert len(parsed["runs"]) == 1

    driver = parsed["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-db-auditor"
    assert driver["version"] == "0.1.0"
    assert len(driver["rules"]) == 10

    sarif_results = parsed["runs"][0]["results"]
    assert len(sarif_results) == 2
    assert sarif_results[0]["ruleId"] == "LH-DB-001"
    assert sarif_results[0]["level"] == "error"


def test_severity_badges_and_output_formats() -> None:
    """Verify severity badges text representation and output format enum values."""
    assert _get_severity_badge(FindingSeverity.CRITICAL).plain == "CRITICAL"
    assert _get_severity_badge(FindingSeverity.HIGH).plain == "HIGH"
    assert _get_severity_badge(FindingSeverity.MEDIUM).plain == "MEDIUM"
    assert _get_severity_badge(FindingSeverity.LOW).plain == "LOW"

    assert OutputFormat.TABLE == "table"
    assert OutputFormat.JSON == "json"
    assert OutputFormat.SARIF == "sarif"
