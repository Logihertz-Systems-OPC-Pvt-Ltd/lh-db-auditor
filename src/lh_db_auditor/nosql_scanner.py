# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        src.lh_db_auditor.nosql_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""NoSQL database configuration scanner for Redis and MongoDB.

Audits redis.conf and mongod.conf for wildcard network bindings, transport encryption,
authentication bypass, dangerous command aliases, server-side JavaScript, and audit trails.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from lh_db_auditor.models import (
    RULES_REGISTRY,
    WILDCARD_IPV4,
    WILDCARD_IPV6,
    DatabaseEngine,
    Finding,
    ScanTargetResult,
)

DANGEROUS_REDIS_COMMANDS = ("FLUSHALL", "FLUSHDB", "CONFIG", "EVAL", "SHUTDOWN", "DEBUG")


def scan_redis_conf(path: Path) -> ScanTargetResult:
    """Scan Redis configuration file (redis.conf)."""
    target_str = str(path)
    result = ScanTargetResult(target=target_str, engine=DatabaseEngine.REDIS)

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        result.error_message = f"Failed to read Redis configuration '{path}': {e}"
        return result

    lines = content.splitlines()
    directives: dict[str, list[tuple[list[str], int]]] = {}

    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        result.parameters_scanned += 1
        tokens = line.split()
        if not tokens:
            continue

        cmd = tokens[0].lower()
        args = tokens[1:]
        directives.setdefault(cmd, []).append((args, idx))

    # LH-DB-002: bind wildcard
    r002 = RULES_REGISTRY["LH-DB-002"]
    if "bind" in directives:
        for args, line_num in directives["bind"]:
            lowered_args = [a.lower() for a in args]
            if any(w in lowered_args for w in (WILDCARD_IPV4, WILDCARD_IPV6, "*", "-::*")):
                result.findings.append(
                    Finding(
                        rule_id=r002.rule_id,
                        severity=r002.severity,
                        category=r002.category,
                        title=r002.title,
                        message=(
                            f"Redis binds to all interfaces ('bind {' '.join(args)}') "
                            f"on line {line_num}."
                        ),
                        target=target_str,
                        engine=DatabaseEngine.REDIS,
                        parameter="bind",
                        value=" ".join(args),
                        line_number=line_num,
                        remediation=r002.remediation,
                    )
                )
    else:
        result.findings.append(
            Finding(
                rule_id=r002.rule_id,
                severity=r002.severity,
                category=r002.category,
                title=r002.title,
                message="Redis lacks a 'bind' directive, defaulting to all interfaces.",
                target=target_str,
                engine=DatabaseEngine.REDIS,
                parameter="bind",
                value="missing",
                remediation=r002.remediation,
            )
        )

    # LH-DB-003: tls-port missing or 0
    r003 = RULES_REGISTRY["LH-DB-003"]
    if "tls-port" in directives:
        for args, line_num in directives["tls-port"]:
            if not args or args[0] in ("0", "no", "off"):
                result.findings.append(
                    Finding(
                        rule_id=r003.rule_id,
                        severity=r003.severity,
                        category=r003.category,
                        title=r003.title,
                        message=(
                            f"Redis TLS port is disabled (tls-port = {' '.join(args)}) "
                            f"on line {line_num}."
                        ),
                        target=target_str,
                        engine=DatabaseEngine.REDIS,
                        parameter="tls-port",
                        value=" ".join(args),
                        line_number=line_num,
                        remediation=r003.remediation,
                    )
                )
    else:
        # Check if plain port is active
        plain_port = "6379"
        if "port" in directives:
            port_args, _ = directives["port"][-1]
            plain_port = port_args[0] if port_args else "6379"

        if plain_port != "0":
            result.findings.append(
                Finding(
                    rule_id=r003.rule_id,
                    severity=r003.severity,
                    category=r003.category,
                    title=r003.title,
                    message=(
                        f"Redis listens on plaintext port {plain_port} without 'tls-port' "
                        f"encryption configured."
                    ),
                    target=target_str,
                    engine=DatabaseEngine.REDIS,
                    parameter="tls-port",
                    value="missing",
                    remediation=r003.remediation,
                )
            )

    # LH-DB-004: missing requirepass / ACL
    r004 = RULES_REGISTRY["LH-DB-004"]
    has_requirepass = "requirepass" in directives and bool(directives["requirepass"])
    has_user_acl = "user" in directives and bool(directives["user"])

    if not has_requirepass and not has_user_acl:
        result.findings.append(
            Finding(
                rule_id=r004.rule_id,
                severity=r004.severity,
                category=r004.category,
                title=r004.title,
                message="Redis lacks authentication (missing requirepass or ACL configuration).",
                target=target_str,
                engine=DatabaseEngine.REDIS,
                parameter="requirepass",
                value="missing",
                remediation=r004.remediation,
            )
        )

    # LH-DB-006: protected-mode no & dangerous commands not disabled
    r006 = RULES_REGISTRY["LH-DB-006"]
    if "protected-mode" in directives:
        for args, line_num in directives["protected-mode"]:
            if args and args[0].lower() in ("no", "off"):
                result.findings.append(
                    Finding(
                        rule_id=r006.rule_id,
                        severity=r006.severity,
                        category=r006.category,
                        title=r006.title,
                        message=(
                            f"Redis protected-mode is disabled (protected-mode {args[0]}) "
                            f"on line {line_num}."
                        ),
                        target=target_str,
                        engine=DatabaseEngine.REDIS,
                        parameter="protected-mode",
                        value=args[0],
                        line_number=line_num,
                        remediation=r006.remediation,
                    )
                )

    # Check renamed / disabled commands
    disabled_cmds: set[str] = set()
    if "rename-command" in directives:
        for args, _line_num in directives["rename-command"]:
            if len(args) >= 2:
                orig_cmd = args[0].upper()
                new_name = args[1]
                # In Redis, rename-command CONFIG "" disables it, or renaming to random string
                if new_name in ('""', "''", "") or new_name != orig_cmd:
                    disabled_cmds.add(orig_cmd)

    missing_disabled = [cmd for cmd in DANGEROUS_REDIS_COMMANDS if cmd not in disabled_cmds]
    if missing_disabled:
        result.findings.append(
            Finding(
                rule_id=r006.rule_id,
                severity=r006.severity,
                category=r006.category,
                title=r006.title,
                message=(
                    f"Dangerous Redis commands ({', '.join(missing_disabled)}) are not disabled "
                    f"via 'rename-command'."
                ),
                target=target_str,
                engine=DatabaseEngine.REDIS,
                parameter="rename-command",
                value=", ".join(missing_disabled),
                remediation=r006.remediation,
                metadata={"unrestricted_commands": missing_disabled},
            )
        )

    # LH-DB-010: Hardcoded plaintext secrets
    r010 = RULES_REGISTRY["LH-DB-010"]
    for secret_directive in ("requirepass", "masterauth"):
        if secret_directive in directives:
            for args, line_num in directives[secret_directive]:
                if args and not args[0].startswith("${") and args[0] not in ('""', "''"):
                    result.findings.append(
                        Finding(
                            rule_id=r010.rule_id,
                            severity=r010.severity,
                            category=r010.category,
                            title=r010.title,
                            message=(
                                f"Redis directive '{secret_directive}' on line {line_num} "
                                f"stores hardcoded plaintext credentials."
                            ),
                            target=target_str,
                            engine=DatabaseEngine.REDIS,
                            parameter=secret_directive,
                            value="[REDACTED]",
                            line_number=line_num,
                            remediation=r010.remediation,
                        )
                    )

    return result


def _find_yaml_line(lines: list[str], key: str, val_substr: str | None = None) -> int | None:
    """Find line number in YAML content for given key and optional value."""
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if key in stripped:
            if val_substr is None or val_substr in stripped:
                return idx
    return None


def scan_mongodb_conf(path: Path) -> ScanTargetResult:
    """Scan MongoDB YAML configuration file (mongod.conf)."""
    target_str = str(path)
    result = ScanTargetResult(target=target_str, engine=DatabaseEngine.MONGODB)

    try:
        content = path.read_text(encoding="utf-8")
        lines = content.splitlines()
        data = yaml.safe_load(content)
    except Exception as e:
        result.error_message = f"Failed to parse MongoDB YAML configuration '{path}': {e}"
        return result

    if not isinstance(data, dict):
        result.error_message = f"MongoDB configuration '{path}' root must be a mapping/dictionary."
        return result

    result.parameters_scanned = len(data)

    net_cfg = data.get("net", {})
    sec_cfg = data.get("security", {})
    audit_cfg = data.get("auditLog", {})

    # LH-DB-002: net.bindIp wildcard or net.bindIpAll: true
    r002 = RULES_REGISTRY["LH-DB-002"]
    bind_ip = str(net_cfg.get("bindIp", ""))
    bind_ip_all = net_cfg.get("bindIpAll")

    if bind_ip_all is True or any(w in bind_ip for w in (WILDCARD_IPV4, WILDCARD_IPV6, "*")):
        line_num = _find_yaml_line(lines, "bindIp") or _find_yaml_line(lines, "bindIpAll")
        val_str = "bindIpAll: true" if bind_ip_all is True else f"bindIp: {bind_ip}"
        result.findings.append(
            Finding(
                rule_id=r002.rule_id,
                severity=r002.severity,
                category=r002.category,
                title=r002.title,
                message=f"MongoDB binds to all network interfaces ({val_str}).",
                target=target_str,
                engine=DatabaseEngine.MONGODB,
                parameter="net.bindIp",
                value=val_str,
                line_number=line_num,
                remediation=r002.remediation,
            )
        )

    # LH-DB-003: net.tls.mode disabled or allowTLS or missing
    r003 = RULES_REGISTRY["LH-DB-003"]
    tls_cfg = net_cfg.get("tls", {})
    ssl_cfg = net_cfg.get("ssl", {})
    tls_mode = str(tls_cfg.get("mode") or ssl_cfg.get("mode") or "").lower()

    if not tls_mode or tls_mode in ("disabled", "allowtls", "preferencetls"):
        line_num = _find_yaml_line(lines, "mode") or _find_yaml_line(lines, "tls")
        val_desc = tls_mode or "missing"
        result.findings.append(
            Finding(
                rule_id=r003.rule_id,
                severity=r003.severity,
                category=r003.category,
                title=r003.title,
                message=(f"MongoDB TLS encryption is not enforced (net.tls.mode: '{val_desc}')."),
                target=target_str,
                engine=DatabaseEngine.MONGODB,
                parameter="net.tls.mode",
                value=val_desc,
                line_number=line_num,
                remediation=r003.remediation,
            )
        )

    # LH-DB-004: security.authorization disabled or missing
    r004 = RULES_REGISTRY["LH-DB-004"]
    auth_val = str(sec_cfg.get("authorization", "")).lower()

    if auth_val != "enabled":
        line_num = _find_yaml_line(lines, "authorization") or _find_yaml_line(lines, "security")
        val_desc = auth_val or "missing"
        result.findings.append(
            Finding(
                rule_id=r004.rule_id,
                severity=r004.severity,
                category=r004.category,
                title=r004.title,
                message=(f"MongoDB RBAC is disabled (security.authorization: '{val_desc}')."),
                target=target_str,
                engine=DatabaseEngine.MONGODB,
                parameter="security.authorization",
                value=val_desc,
                line_number=line_num,
                remediation=r004.remediation,
            )
        )

    # LH-DB-007: security.javascriptEnabled: true or net.http.enabled: true
    r007 = RULES_REGISTRY["LH-DB-007"]
    js_enabled = sec_cfg.get("javascriptEnabled")
    if js_enabled is True:
        line_num = _find_yaml_line(lines, "javascriptEnabled")
        result.findings.append(
            Finding(
                rule_id=r007.rule_id,
                severity=r007.severity,
                category=r007.category,
                title=r007.title,
                message=(
                    "MongoDB server-side JavaScript execution is enabled "
                    "(security.javascriptEnabled: true)."
                ),
                target=target_str,
                engine=DatabaseEngine.MONGODB,
                parameter="security.javascriptEnabled",
                value="true",
                line_number=line_num,
                remediation=r007.remediation,
            )
        )

    http_cfg = net_cfg.get("http", {})
    if (
        http_cfg.get("enabled") is True
        or http_cfg.get("RESTInterfaceEnabled") is True
        or http_cfg.get("JSONPEnabled") is True
    ):
        line_num = _find_yaml_line(lines, "http")
        result.findings.append(
            Finding(
                rule_id=r007.rule_id,
                severity=r007.severity,
                category=r007.category,
                title=r007.title,
                message=("MongoDB legacy HTTP or REST web interface is enabled in network config."),
                target=target_str,
                engine=DatabaseEngine.MONGODB,
                parameter="net.http.enabled",
                value="true",
                line_number=line_num,
                remediation=r007.remediation,
            )
        )

    # LH-DB-009: Missing auditLog
    r009 = RULES_REGISTRY["LH-DB-009"]
    dest = audit_cfg.get("destination")
    if not audit_cfg or not dest:
        line_num = _find_yaml_line(lines, "auditLog")
        result.findings.append(
            Finding(
                rule_id=r009.rule_id,
                severity=r009.severity,
                category=r009.category,
                title=r009.title,
                message=(
                    "MongoDB audit logging is missing or unconfigured "
                    "(missing 'auditLog.destination')."
                ),
                target=target_str,
                engine=DatabaseEngine.MONGODB,
                parameter="auditLog.destination",
                value="missing",
                line_number=line_num,
                remediation=r009.remediation,
            )
        )

    return result
