# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        src.lh_db_auditor.mysql_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""MySQL and MariaDB configuration scanner.

Audits my.cnf and mysqld.cnf for wildcard network bindings, unforced TLS,
skip-grant-tables bypass, local_infile / secure_file_priv vulnerabilities,
legacy authentication plugins, missing logs, and plaintext secrets.
"""

from __future__ import annotations

from pathlib import Path

from lh_db_auditor.models import (
    RULES_REGISTRY,
    WILDCARD_IPV4,
    WILDCARD_IPV6,
    DatabaseEngine,
    Finding,
    ScanTargetResult,
)


def _clean_val(val: str) -> str:
    """Strip quotes and whitespace from config values."""
    s = val.strip()
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        return s[1:-1].strip()
    return s


def scan_mysql_conf(path: Path) -> ScanTargetResult:
    """Scan MySQL/MariaDB configuration file (my.cnf, mysqld.cnf)."""
    target_str = str(path)
    result = ScanTargetResult(target=target_str, engine=DatabaseEngine.MYSQL)

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        result.error_message = f"Failed to read MySQL configuration '{path}': {e}"
        return result

    lines = content.splitlines()
    params: dict[str, tuple[str, int]] = {}
    flags_present: dict[str, int] = {}

    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "!")):
            continue

        if line.startswith("[") and line.endswith("]"):
            continue

        result.parameters_scanned += 1

        # Check for flags without = (e.g. skip-grant-tables)
        if "=" in line:
            key, val = line.split("=", 1)
            k = key.strip().lower().replace("_", "-")
            v = _clean_val(val)
            params[k] = (v, idx)

            # LH-DB-010: Hardcoded plaintext credentials
            if (
                any(secret in k for secret in ("password", "secret", "bind-dn-password"))
                and v
                and not v.startswith("${")
            ):
                r010 = RULES_REGISTRY["LH-DB-010"]
                result.findings.append(
                    Finding(
                        rule_id=r010.rule_id,
                        severity=r010.severity,
                        category=r010.category,
                        title=r010.title,
                        message=(
                            f"MySQL configuration parameter '{k}' on line {idx} "
                            f"stores hardcoded plaintext password credentials."
                        ),
                        target=target_str,
                        engine=DatabaseEngine.MYSQL,
                        parameter=k,
                        value="[REDACTED]",
                        line_number=idx,
                        remediation=r010.remediation,
                    )
                )
        else:
            flag_key = line.strip().lower().replace("_", "-")
            flags_present[flag_key] = idx
            params[flag_key] = ("on", idx)

    # LH-DB-004: skip-grant-tables (Critical Auth Bypass)
    r004 = RULES_REGISTRY["LH-DB-004"]
    if "skip-grant-tables" in flags_present or "skip-grant-tables" in params:
        val, line_num = params.get(
            "skip-grant-tables", ("on", flags_present.get("skip-grant-tables", 1))
        )
        if val.lower() not in ("off", "0", "false"):
            result.findings.append(
                Finding(
                    rule_id=r004.rule_id,
                    severity=r004.severity,
                    category=r004.category,
                    title=r004.title,
                    message=(
                        f"MySQL authentication bypass via 'skip-grant-tables' on line {line_num}."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="skip-grant-tables",
                    value=val,
                    line_number=line_num,
                    remediation=r004.remediation,
                )
            )

    # LH-DB-002: bind-address wildcard
    if "bind-address" in params:
        val, line_num = params["bind-address"]
        v_clean = val.lower().strip()
        if v_clean in (WILDCARD_IPV4, WILDCARD_IPV6, "*") or v_clean.startswith(WILDCARD_IPV4):
            r002 = RULES_REGISTRY["LH-DB-002"]
            result.findings.append(
                Finding(
                    rule_id=r002.rule_id,
                    severity=r002.severity,
                    category=r002.category,
                    title=r002.title,
                    message=(
                        f"MySQL server binds to all network interfaces (bind-address = '{val}') "
                        f"on line {line_num}."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="bind-address",
                    value=val,
                    line_number=line_num,
                    remediation=r002.remediation,
                )
            )

    # LH-DB-003: require_secure_transport disabled or missing
    r003 = RULES_REGISTRY["LH-DB-003"]
    if "require-secure-transport" in params:
        val, line_num = params["require-secure-transport"]
        if val.lower() in ("off", "0", "false", "no"):
            result.findings.append(
                Finding(
                    rule_id=r003.rule_id,
                    severity=r003.severity,
                    category=r003.category,
                    title=r003.title,
                    message=(
                        f"MySQL require_secure_transport is disabled "
                        f"(require-secure-transport = '{val}') on line {line_num}."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="require_secure_transport",
                    value=val,
                    line_number=line_num,
                    remediation=r003.remediation,
                )
            )
    elif "ssl" in params:
        val, line_num = params["ssl"]
        if val.lower() in ("off", "0", "false", "no"):
            result.findings.append(
                Finding(
                    rule_id=r003.rule_id,
                    severity=r003.severity,
                    category=r003.category,
                    title=r003.title,
                    message=f"MySQL SSL encryption is disabled (ssl = '{val}') on line {line_num}.",
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="ssl",
                    value=val,
                    line_number=line_num,
                    remediation=r003.remediation,
                )
            )
    else:
        result.findings.append(
            Finding(
                rule_id=r003.rule_id,
                severity=r003.severity,
                category=r003.category,
                title=r003.title,
                message="MySQL require_secure_transport is not enforced in server configuration.",
                target=target_str,
                engine=DatabaseEngine.MYSQL,
                parameter="require_secure_transport",
                value="missing",
                remediation=r003.remediation,
            )
        )

    # LH-DB-005: local_infile = 1 and empty/unrestricted secure_file_priv
    r005 = RULES_REGISTRY["LH-DB-005"]
    if "local-infile" in params:
        val, line_num = params["local-infile"]
        if val.lower() in ("1", "on", "true", "yes"):
            result.findings.append(
                Finding(
                    rule_id=r005.rule_id,
                    severity=r005.severity,
                    category=r005.category,
                    title=r005.title,
                    message=(
                        f"MySQL enables arbitrary client local file reads (local_infile = '{val}') "
                        f"on line {line_num}."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="local_infile",
                    value=val,
                    line_number=line_num,
                    remediation=r005.remediation,
                )
            )

    if "secure-file-priv" in params:
        val, line_num = params["secure-file-priv"]
        # In MySQL, secure_file_priv = "" (empty string) disables protection entirely!
        if val.strip() in ('""', "''", ""):
            result.findings.append(
                Finding(
                    rule_id=r005.rule_id,
                    severity=r005.severity,
                    category=r005.category,
                    title=r005.title,
                    message=(
                        f"MySQL secure_file_priv is unrestricted/empty on line {line_num}, "
                        f"allowing arbitrary file import/export operations."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="secure_file_priv",
                    value=val,
                    line_number=line_num,
                    remediation=r005.remediation,
                )
            )

    # LH-DB-008: default_authentication_plugin weak algorithm
    if "default-authentication-plugin" in params:
        val, line_num = params["default-authentication-plugin"]
        if val.lower() in ("mysql_native_password", "sha256_password"):
            r008 = RULES_REGISTRY["LH-DB-008"]
            result.findings.append(
                Finding(
                    rule_id=r008.rule_id,
                    severity=r008.severity,
                    category=r008.category,
                    title=r008.title,
                    message=(
                        f"MySQL default_authentication_plugin on line {line_num} uses legacy "
                        f"'{val}' algorithm instead of 'caching_sha2_password'."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="default_authentication_plugin",
                    value=val,
                    line_number=line_num,
                    remediation=r008.remediation,
                )
            )

    # LH-DB-009: Missing audit / general / error logging
    if "general-log" in params:
        val, line_num = params["general-log"]
        if val.lower() in ("off", "0", "false", "no"):
            r009 = RULES_REGISTRY["LH-DB-009"]
            result.findings.append(
                Finding(
                    rule_id=r009.rule_id,
                    severity=r009.severity,
                    category=r009.category,
                    title=r009.title,
                    message=(
                        f"MySQL general_log is disabled (general-log = '{val}') on line {line_num}."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.MYSQL,
                    parameter="general_log",
                    value=val,
                    line_number=line_num,
                    remediation=r009.remediation,
                )
            )

    return result
