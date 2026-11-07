# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        src.lh_db_auditor.postgres_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""PostgreSQL configuration file and client authentication scanner.

Audits postgresql.conf and pg_hba.conf for authentication risks, wildcard network bindings,
disabled SSL/TLS, weak password hashing, missing audit logging, and hardcoded secrets.
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


def scan_pg_hba(path: Path) -> ScanTargetResult:
    """Scan PostgreSQL pg_hba.conf host-based authentication rules."""
    target_str = str(path)
    result = ScanTargetResult(target=target_str, engine=DatabaseEngine.POSTGRESQL)

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        result.error_message = f"Failed to read pg_hba.conf '{path}': {e}"
        return result

    lines = content.splitlines()
    rule001 = RULES_REGISTRY["LH-DB-001"]
    rule010 = RULES_REGISTRY["LH-DB-010"]

    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        result.parameters_scanned += 1
        # Tokenize line respecting possible tokens
        tokens = line.split()
        if not tokens:
            continue

        conn_type = tokens[0].lower()
        if conn_type not in (
            "local",
            "host",
            "hostssl",
            "hostnossl",
            "hostgssenc",
            "hostnogssenc",
        ):
            continue

        # In pg_hba.conf:
        # local: TYPE DATABASE USER METHOD [OPTIONS]
        # host*: TYPE DATABASE USER ADDRESS [IP-MASK] METHOD [OPTIONS]
        if conn_type == "local":
            if len(tokens) < 4:
                continue
            auth_method = tokens[3].lower()
            address = "local"
            options = tokens[4:]
        else:
            if len(tokens) < 5:
                continue
            # Handle IP + Netmask or CIDR
            # e.g., host all all 0.0.0.0 0.0.0.0 md5
            # or    host all all 0.0.0.0/0 md5
            if len(tokens) >= 6 and "/" not in tokens[3] and tokens[4].count(".") == 3:
                address = f"{tokens[3]}/{tokens[4]}"
                auth_method = tokens[5].lower()
                options = tokens[6:]
            else:
                address = tokens[3]
                auth_method = tokens[4].lower()
                options = tokens[5:]

        # LH-DB-001: Insecure auth method or unrestricted CIDR
        is_insecure_auth = auth_method in ("trust", "password", "md5", "ident")
        is_unrestricted_cidr = address.lower() in (
            "0.0.0.0/0",
            "::/0",
            "all",
            "0.0.0.0/0.0.0.0",
        )

        if is_insecure_auth:
            result.findings.append(
                Finding(
                    rule_id=rule001.rule_id,
                    severity=rule001.severity,
                    category=rule001.category,
                    title=rule001.title,
                    message=(
                        f"pg_hba.conf rule on line {idx} permits insecure '{auth_method}' "
                        f"authentication for address '{address}'."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.POSTGRESQL,
                    parameter=f"{conn_type} {address}",
                    value=auth_method,
                    line_number=idx,
                    remediation=rule001.remediation,
                    metadata={"conn_type": conn_type, "address": address, "auth": auth_method},
                )
            )

        if is_unrestricted_cidr and conn_type != "local":
            result.findings.append(
                Finding(
                    rule_id=rule001.rule_id,
                    severity=rule001.severity,
                    category=rule001.category,
                    title=rule001.title,
                    message=(
                        f"pg_hba.conf rule on line {idx} allows unrestricted network access "
                        f"from CIDR '{address}' with method '{auth_method}'."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.POSTGRESQL,
                    parameter=f"{conn_type} {address}",
                    value=address,
                    line_number=idx,
                    remediation=rule001.remediation,
                    metadata={"conn_type": conn_type, "address": address, "auth": auth_method},
                )
            )

        # LH-DB-010: Check options for plaintext secrets
        if options:
            opts_str = " ".join(options)
            if any(k in opts_str.lower() for k in ("password=", "secret=", "token=")):
                result.findings.append(
                    Finding(
                        rule_id=rule010.rule_id,
                        severity=rule010.severity,
                        category=rule010.category,
                        title=rule010.title,
                        message=(
                            f"pg_hba.conf rule on line {idx} contains hardcoded plaintext "
                            f"credential options: '{opts_str}'."
                        ),
                        target=target_str,
                        engine=DatabaseEngine.POSTGRESQL,
                        parameter="options",
                        value=opts_str,
                        line_number=idx,
                        remediation=rule010.remediation,
                    )
                )

    return result


def scan_postgresql_conf(path: Path) -> ScanTargetResult:
    """Scan PostgreSQL postgresql.conf server configuration file."""
    target_str = str(path)
    result = ScanTargetResult(target=target_str, engine=DatabaseEngine.POSTGRESQL)

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        result.error_message = f"Failed to read postgresql.conf '{path}': {e}"
        return result

    lines = content.splitlines()
    params: dict[str, tuple[str, int]] = {}

    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip inline comment after value, taking into account single-quoted strings
        # e.g. listen_addresses = '*' # what IP address(es) to listen on;
        in_quote = False
        clean_parts: list[str] = []
        for ch in line:
            if ch == "'":
                in_quote = not in_quote
            elif ch == "#" and not in_quote:
                break
            clean_parts.append(ch)

        clean_line = "".join(clean_parts).strip()
        if "=" in clean_line:
            key, val = clean_line.split("=", 1)
            k = key.strip().lower()
            v = _clean_val(val)
            params[k] = (v, idx)
            result.parameters_scanned += 1

            # LH-DB-010: Check hardcoded passwords in line values
            is_secret = (
                k in ("password", "sslpassword", "bind_dn_password")
                or ("conninfo" in k and "password=" in v.lower())
                or ("password" in k and "encryption" not in k and "hash" not in k)
            )
            if is_secret and v and not v.startswith("${"):
                r010 = RULES_REGISTRY["LH-DB-010"]
                result.findings.append(
                    Finding(
                        rule_id=r010.rule_id,
                        severity=r010.severity,
                        category=r010.category,
                        title=r010.title,
                        message=(
                            f"PostgreSQL configuration parameter '{k}' on line {idx} "
                            f"stores hardcoded plaintext credentials."
                        ),
                        target=target_str,
                        engine=DatabaseEngine.POSTGRESQL,
                        parameter=k,
                        value="[REDACTED]",
                        line_number=idx,
                        remediation=r010.remediation,
                    )
                )

    # LH-DB-002: listen_addresses wildcard
    if "listen_addresses" in params:
        val, line_num = params["listen_addresses"]
        v_clean = val.lower().replace(" ", "")
        if "*" in v_clean or WILDCARD_IPV4 in v_clean or WILDCARD_IPV6 in v_clean:
            r002 = RULES_REGISTRY["LH-DB-002"]
            result.findings.append(
                Finding(
                    rule_id=r002.rule_id,
                    severity=r002.severity,
                    category=r002.category,
                    title=r002.title,
                    message=(
                        f"PostgreSQL server binds to all interfaces (listen_addresses = '{val}') "
                        f"on line {line_num}."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.POSTGRESQL,
                    parameter="listen_addresses",
                    value=val,
                    line_number=line_num,
                    remediation=r002.remediation,
                )
            )

    # LH-DB-003: ssl = off or missing
    r003 = RULES_REGISTRY["LH-DB-003"]
    if "ssl" in params:
        val, line_num = params["ssl"]
        if val.lower() in ("off", "false", "0", "no"):
            result.findings.append(
                Finding(
                    rule_id=r003.rule_id,
                    severity=r003.severity,
                    category=r003.category,
                    title=r003.title,
                    message=(
                        f"PostgreSQL SSL encryption is disabled (ssl = '{val}') on line {line_num}."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.POSTGRESQL,
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
                message=(
                    "PostgreSQL SSL transport encryption is not configured or enabled "
                    "(missing 'ssl = on')."
                ),
                target=target_str,
                engine=DatabaseEngine.POSTGRESQL,
                parameter="ssl",
                value="missing",
                remediation=r003.remediation,
            )
        )

    # LH-DB-008: password_encryption = md5
    if "password_encryption" in params:
        val, line_num = params["password_encryption"]
        if val.lower() in ("md5", "on", "plain"):
            r008 = RULES_REGISTRY["LH-DB-008"]
            result.findings.append(
                Finding(
                    rule_id=r008.rule_id,
                    severity=r008.severity,
                    category=r008.category,
                    title=r008.title,
                    message=(
                        f"PostgreSQL password_encryption on line {line_num} uses weak algorithm "
                        f"'{val}' instead of 'scram-sha-256'."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.POSTGRESQL,
                    parameter="password_encryption",
                    value=val,
                    line_number=line_num,
                    remediation=r008.remediation,
                )
            )

    # LH-DB-009: Logging parameters
    r009 = RULES_REGISTRY["LH-DB-009"]
    for log_param in ("log_connections", "log_disconnections"):
        if log_param in params:
            val, line_num = params[log_param]
            if val.lower() in ("off", "false", "0", "no"):
                result.findings.append(
                    Finding(
                        rule_id=r009.rule_id,
                        severity=r009.severity,
                        category=r009.category,
                        title=r009.title,
                        message=(
                            f"PostgreSQL audit parameter '{log_param}' on line {line_num} "
                            f"is disabled ({log_param} = '{val}')."
                        ),
                        target=target_str,
                        engine=DatabaseEngine.POSTGRESQL,
                        parameter=log_param,
                        value=val,
                        line_number=line_num,
                        remediation=r009.remediation,
                    )
                )

    if "log_statement" in params:
        val, line_num = params["log_statement"]
        if val.lower() in ("none", "off", ""):
            result.findings.append(
                Finding(
                    rule_id=r009.rule_id,
                    severity=r009.severity,
                    category=r009.category,
                    title=r009.title,
                    message=(
                        f"PostgreSQL log_statement on line {line_num} is set to '{val}', "
                        f"disabling DDL and statement audit logging."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.POSTGRESQL,
                    parameter="log_statement",
                    value=val,
                    line_number=line_num,
                    remediation=r009.remediation,
                )
            )

    return result
