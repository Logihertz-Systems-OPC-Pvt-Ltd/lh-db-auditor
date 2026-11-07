# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        tests.test_nosql_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for NoSQL configuration scanners (Redis & MongoDB)."""

from __future__ import annotations

from pathlib import Path

from lh_db_auditor.models import DatabaseEngine, FindingSeverity
from lh_db_auditor.nosql_scanner import scan_mongodb_conf, scan_redis_conf


def test_clean_redis_conf(clean_redis_file: Path) -> None:
    """Verify that hardened redis.conf yields zero findings."""
    res = scan_redis_conf(clean_redis_file)
    assert res.error_message is None
    assert res.engine == DatabaseEngine.REDIS
    assert len(res.findings) == 0


def test_clean_mongod_conf(clean_mongod_file: Path) -> None:
    """Verify that hardened mongod.conf yields zero findings."""
    res = scan_mongodb_conf(clean_mongod_file)
    assert res.error_message is None
    assert res.engine == DatabaseEngine.MONGODB
    assert len(res.findings) == 0


def test_vulnerable_redis_conf(vulnerable_redis_file: Path) -> None:
    """Verify detection of wildcard bind, unencrypted port, missing ACL/auth, and secrets."""
    res = scan_redis_conf(vulnerable_redis_file)
    rule_ids = [f.rule_id for f in res.findings]

    assert "LH-DB-002" in rule_ids  # bind 0.0.0.0
    assert "LH-DB-003" in rule_ids  # plaintext port without tls-port
    assert "LH-DB-006" in rule_ids  # protected-mode no & unrenamed commands
    assert "LH-DB-010" in rule_ids  # requirepass plaintext password


def test_vulnerable_mongod_conf(vulnerable_mongod_file: Path) -> None:
    """Verify detection of wildcard bindIp, disabled TLS, disabled auth, JS, and missing audit."""
    res = scan_mongodb_conf(vulnerable_mongod_file)
    rule_ids = [f.rule_id for f in res.findings]

    assert "LH-DB-002" in rule_ids  # bindIp: 0.0.0.0
    assert "LH-DB-003" in rule_ids  # tls.mode: disabled
    assert "LH-DB-004" in rule_ids  # security.authorization: disabled
    assert "LH-DB-007" in rule_ids  # javascriptEnabled: true and http.enabled: true
    assert "LH-DB-009" in rule_ids  # missing auditLog

    f004 = next(f for f in res.findings if f.rule_id == "LH-DB-004")
    assert f004.severity == FindingSeverity.CRITICAL


def test_nosql_error_handling(tmp_path: Path) -> None:
    """Verify handling of missing or corrupt files."""
    missing = tmp_path / "missing.conf"
    res_r = scan_redis_conf(missing)
    assert res_r.error_message is not None

    corrupt = tmp_path / "corrupt.yaml"
    corrupt.write_text("key: [unclosed", encoding="utf-8")
    res_m = scan_mongodb_conf(corrupt)
    assert res_m.error_message is not None
    assert "Failed to parse" in res_m.error_message
