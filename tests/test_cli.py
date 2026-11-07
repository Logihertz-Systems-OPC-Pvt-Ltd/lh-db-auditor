# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit and integration tests for the lh-db CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_db_auditor.cli import app

runner = CliRunner()
CLI_ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_help() -> None:
    """Verify that --help exits cleanly with usage information."""
    result = runner.invoke(app, ["--help"], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Enterprise database security posture auditor" in result.output
    assert "scan" in result.output
    assert "rules" in result.output


def test_cli_rules_list() -> None:
    """Verify that 'rules' command lists all 10 LH-DB detection rules."""
    result = runner.invoke(app, ["rules"], env=CLI_ENV)
    assert result.exit_code == 0
    assert "LH-DB Database Security Detection Rules" in result.output
    for i in range(1, 11):
        assert f"LH-DB-{i:03d}" in result.output


def test_cli_scan_clean_configs(
    clean_postgres_files: tuple[Path, Path],
    clean_mysql_file: Path,
) -> None:
    """Verify scanning clean database configurations returns exit code 0."""
    conf, hba = clean_postgres_files
    res1 = runner.invoke(app, ["scan", str(conf)], env=CLI_ENV)
    assert res1.exit_code == 0
    assert "Clean Audit" in res1.output

    res2 = runner.invoke(app, ["scan", str(hba)], env=CLI_ENV)
    assert res2.exit_code == 0

    res3 = runner.invoke(app, ["scan", str(clean_mysql_file)], env=CLI_ENV)
    assert res3.exit_code == 0


def test_cli_scan_vulnerable_config(vulnerable_mysql_file: Path) -> None:
    """Verify scanning vulnerable configuration returns exit code 1."""
    result = runner.invoke(app, ["scan", str(vulnerable_mysql_file)], env=CLI_ENV)
    assert result.exit_code == 1
    assert "LH-DB-004" in result.output
    assert "Database Security Findings" in result.output


def test_cli_scan_json_output(clean_mysql_file: Path) -> None:
    """Verify scanning with --format json outputs valid JSON."""
    result = runner.invoke(
        app,
        ["scan", str(clean_mysql_file), "--format", "json"],
        env=CLI_ENV,
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["report_type"] == "database_security_audit"
    assert parsed["summary"]["total_findings"] == 0


def test_cli_scan_sarif_output(vulnerable_mysql_file: Path) -> None:
    """Verify scanning with --format sarif outputs valid SARIF."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_mysql_file), "--format", "sarif"],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"][0]["results"]) > 0


def test_cli_scan_output_file(clean_mysql_file: Path, tmp_path: Path) -> None:
    """Verify that --output writes report to disk."""
    out_file = tmp_path / "out_report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(clean_mysql_file),
            "--format",
            "json",
            "--output",
            str(out_file),
        ],
        env=CLI_ENV,
    )
    assert result.exit_code == 0
    assert out_file.exists()
    parsed = json.loads(out_file.read_text(encoding="utf-8"))
    assert parsed["report_type"] == "database_security_audit"


def test_cli_scan_fail_on_threshold(tmp_path: Path) -> None:
    """Verify --fail-on allows passing when findings are below the threshold."""
    # Config triggering only LH-DB-008 (MEDIUM)
    med_conf = tmp_path / "postgresql.conf"
    med_conf.write_text(
        """
listen_addresses = '127.0.0.1'
ssl = on
password_encryption = md5
log_connections = on
log_disconnections = on
log_statement = ddl
""".strip(),
        encoding="utf-8",
    )
    # Default fail-on is HIGH -> should pass with exit code 0
    result = runner.invoke(app, ["scan", str(med_conf)], env=CLI_ENV)
    assert result.exit_code == 0

    # Explicit fail-on MEDIUM -> should fail with exit code 1
    result_fail = runner.invoke(
        app,
        ["scan", str(med_conf), "--fail-on", "MEDIUM"],
        env=CLI_ENV,
    )
    assert result_fail.exit_code == 1


def test_cli_scan_min_severity_filter(vulnerable_mysql_file: Path) -> None:
    """Verify --min-severity filters out findings below the specified level."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(vulnerable_mysql_file),
            "--format",
            "json",
            "--min-severity",
            "CRITICAL",
        ],
        env=CLI_ENV,
    )
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    for res in parsed["results"]:
        for f in res["findings"]:
            assert f["severity"] == "CRITICAL"


def test_cli_scan_directory(clean_postgres_files: tuple[Path, Path], tmp_path: Path) -> None:
    """Verify scanning directory containing database configuration files."""
    result = runner.invoke(app, ["scan", str(tmp_path)], env=CLI_ENV)
    assert result.exit_code == 0
    assert "Clean Audit" in result.output


def test_cli_scan_nonexistent_target(tmp_path: Path) -> None:
    """Verify scanning nonexistent path returns exit code 2."""
    missing = tmp_path / "does_not_exist.conf"
    result = runner.invoke(app, ["scan", str(missing)], env=CLI_ENV)
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_cli_scan_generic_file_detection(tmp_path: Path) -> None:
    """Verify content-based detection for generic filename."""
    generic_mysql = tmp_path / "custom_db.conf"
    generic_mysql.write_text("[mysqld]\nlocal_infile = 1\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(generic_mysql)], env=CLI_ENV)
    assert "LH-DB-005" in result.output


def test_cli_scan_empty_directory(tmp_path: Path) -> None:
    """Verify scanning empty directory handles no-configs gracefully."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    result = runner.invoke(app, ["scan", str(empty_dir)], env=CLI_ENV)
    assert result.exit_code == 0
    assert "No database configuration files found" in result.output
