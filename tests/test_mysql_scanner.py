# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        tests.test_mysql_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for MySQL and MariaDB configuration scanner."""

from __future__ import annotations

from pathlib import Path

from lh_db_auditor.models import DatabaseEngine, FindingSeverity
from lh_db_auditor.mysql_scanner import scan_mysql_conf


def test_clean_mysql_cnf(clean_mysql_file: Path) -> None:
    """Verify that hardened my.cnf yields zero findings."""
    res = scan_mysql_conf(clean_mysql_file)
    assert res.error_message is None
    assert res.engine == DatabaseEngine.MYSQL
    assert len(res.findings) == 0


def test_vulnerable_mysql_cnf(vulnerable_mysql_file: Path) -> None:
    """Verify detection of wildcard bind, TLS, skip-grant-tables, local_infile, and secrets."""
    res = scan_mysql_conf(vulnerable_mysql_file)
    rule_ids = [f.rule_id for f in res.findings]

    assert "LH-DB-002" in rule_ids  # bind-address = 0.0.0.0
    assert "LH-DB-003" in rule_ids  # require_secure_transport = OFF
    assert "LH-DB-004" in rule_ids  # skip-grant-tables
    assert "LH-DB-005" in rule_ids  # local_infile = 1 and secure_file_priv = ""
    assert "LH-DB-008" in rule_ids  # mysql_native_password
    assert "LH-DB-010" in rule_ids  # hardcoded password

    f004 = next(f for f in res.findings if f.rule_id == "LH-DB-004")
    assert f004.severity == FindingSeverity.CRITICAL


def test_missing_mysql_file(tmp_path: Path) -> None:
    """Verify graceful error reporting when MySQL config does not exist."""
    missing = tmp_path / "missing.cnf"
    res = scan_mysql_conf(missing)
    assert res.error_message is not None
    assert "Failed to read" in res.error_message


def test_mysql_ssl_and_general_log_disabled(tmp_path: Path) -> None:
    """Verify detection when ssl = 0 and general-log = OFF."""
    cnf = tmp_path / "ssl_off.cnf"
    cnf.write_text(
        "[mysqld]\nssl = 0\ngeneral_log = OFF\nrequire_secure_transport = 0\n",
        encoding="utf-8",
    )
    res = scan_mysql_conf(cnf)
    rule_ids = [f.rule_id for f in res.findings]
    assert "LH-DB-003" in rule_ids
    assert "LH-DB-009" in rule_ids
