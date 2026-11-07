# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        tests.test_postgres_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for PostgreSQL configuration and pg_hba.conf scanner."""

from __future__ import annotations

from pathlib import Path

from lh_db_auditor.models import DatabaseEngine, FindingSeverity
from lh_db_auditor.postgres_scanner import scan_pg_hba, scan_postgresql_conf


def test_clean_pg_hba(clean_postgres_files: tuple[Path, Path]) -> None:
    """Verify that hardened pg_hba.conf yields zero findings."""
    _, hba = clean_postgres_files
    res = scan_pg_hba(hba)
    assert res.error_message is None
    assert res.engine == DatabaseEngine.POSTGRESQL
    assert len(res.findings) == 0


def test_clean_postgresql_conf(clean_postgres_files: tuple[Path, Path]) -> None:
    """Verify that hardened postgresql.conf yields zero findings."""
    conf, _ = clean_postgres_files
    res = scan_postgresql_conf(conf)
    assert res.error_message is None
    assert res.engine == DatabaseEngine.POSTGRESQL
    assert len(res.findings) == 0


def test_vulnerable_pg_hba(vulnerable_postgres_files: tuple[Path, Path]) -> None:
    """Verify detection of trust, cleartext password, and 0.0.0.0/0 in pg_hba.conf."""
    _, hba = vulnerable_postgres_files
    res = scan_pg_hba(hba)
    rule_ids = [f.rule_id for f in res.findings]
    assert "LH-DB-001" in rule_ids
    f001 = next(f for f in res.findings if f.rule_id == "LH-DB-001")
    assert f001.severity == FindingSeverity.CRITICAL


def test_vulnerable_postgresql_conf(vulnerable_postgres_files: tuple[Path, Path]) -> None:
    """Verify detection of wildcard listen_addresses, ssl=off, weak md5, logging, and secrets."""
    conf, _ = vulnerable_postgres_files
    res = scan_postgresql_conf(conf)
    rule_ids = [f.rule_id for f in res.findings]

    assert "LH-DB-002" in rule_ids  # listen_addresses = '*'
    assert "LH-DB-003" in rule_ids  # ssl = off
    assert "LH-DB-008" in rule_ids  # password_encryption = md5
    assert "LH-DB-009" in rule_ids  # log_connections/disconnections/statement
    assert "LH-DB-010" in rule_ids  # password = '...'


def test_missing_files_error_handling(tmp_path: Path) -> None:
    """Verify graceful error reporting when config files do not exist."""
    missing = tmp_path / "nonexistent.conf"
    res_hba = scan_pg_hba(missing)
    assert res_hba.error_message is not None
    assert "Failed to read" in res_hba.error_message

    res_conf = scan_postgresql_conf(missing)
    assert res_conf.error_message is not None
    assert "Failed to read" in res_conf.error_message
