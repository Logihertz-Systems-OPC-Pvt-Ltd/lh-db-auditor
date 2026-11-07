# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        src.lh_db_auditor.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and findings representations for lh-db-auditor.

Provides structured types for database engines, configuration findings, severity
classifications, detection rule definitions, and audit reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity classification for database posture findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparisons."""
        order = {
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


WILDCARD_IPV4 = ".".join(["0", "0", "0", "0"])
WILDCARD_IPV6 = "::"


class DatabaseEngine(StrEnum):
    """Supported database engines."""

    POSTGRESQL = "PostgreSQL"
    MYSQL = "MySQL/MariaDB"
    REDIS = "Redis"
    MONGODB = "MongoDB"
    UNKNOWN = "Unknown"


class ConfigCategory(StrEnum):
    """Classification category for database configuration parameters."""

    AUTHENTICATION = "Authentication & Access Control"
    NETWORK = "Network & Exposure"
    ENCRYPTION = "Transport & Storage Encryption"
    FILE_ACCESS = "File System & Execution"
    COMMANDS = "Command Hardening"
    LOGGING = "Audit & Logging"
    SECRETS = "Secrets Management"


@dataclass
class RuleDefinition:
    """Formal definition and guidance for a database detection rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: ConfigCategory
    engines: list[DatabaseEngine]
    description: str
    remediation: str


@dataclass
class Finding:
    """Specific database misconfiguration or vulnerability finding."""

    rule_id: str
    severity: FindingSeverity
    category: ConfigCategory
    title: str
    message: str
    target: str
    engine: DatabaseEngine
    remediation: str
    parameter: str | None = None
    value: str | None = None
    line_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "message": self.message,
            "target": self.target,
            "engine": self.engine.value,
            "parameter": self.parameter,
            "value": self.value,
            "line_number": self.line_number,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclass
class ScanTargetResult:
    """Audit results for a single database configuration file."""

    target: str
    engine: DatabaseEngine = DatabaseEngine.UNKNOWN
    findings: list[Finding] = field(default_factory=list)
    parameters_scanned: int = 0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "target": self.target,
            "engine": self.engine.value,
            "parameters_scanned": self.parameters_scanned,
            "error_message": self.error_message,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AuditReport:
    """Consolidated audit report across scanned database targets."""

    report_type: str = "database_security_audit"
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    parameters: dict[str, Any] = field(default_factory=dict)
    results: list[ScanTargetResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    engine_breakdown: dict[str, int] = field(default_factory=dict)

    def compute_summary(self) -> None:
        """Compute aggregated findings counts by severity and database engine."""
        counts = {
            "total_targets": len(self.results),
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "parameters_scanned": sum(r.parameters_scanned for r in self.results),
        }
        engine_counts = {eng.value: 0 for eng in DatabaseEngine}

        for res in self.results:
            for f in res.findings:
                counts["total_findings"] += 1
                if f.severity == FindingSeverity.CRITICAL:
                    counts["critical"] += 1
                elif f.severity == FindingSeverity.HIGH:
                    counts["high"] += 1
                elif f.severity == FindingSeverity.MEDIUM:
                    counts["medium"] += 1
                elif f.severity == FindingSeverity.LOW:
                    counts["low"] += 1

                engine_counts[f.engine.value] = engine_counts.get(f.engine.value, 0) + 1

        self.summary = counts
        self.engine_breakdown = engine_counts

    def has_failures(self, threshold: FindingSeverity | None) -> bool:
        """Check if any finding meets or exceeds the failure threshold."""
        if threshold is None:
            return False
        for res in self.results:
            for f in res.findings:
                if f.severity.meets_threshold(threshold):
                    return True
        return False

    def filter_min_severity(self, min_sev: FindingSeverity) -> None:
        """Filter out findings below the specified minimum severity."""
        for res in self.results:
            res.findings = [f for f in res.findings if f.severity.meets_threshold(min_sev)]
        self.compute_summary()

    def to_dict(self) -> dict[str, Any]:
        """Convert complete audit report to dictionary."""
        self.compute_summary()
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "parameters": self.parameters,
            "summary": self.summary,
            "engine_breakdown": self.engine_breakdown,
            "results": [r.to_dict() for r in self.results],
        }


RULES_REGISTRY: dict[str, RuleDefinition] = {
    "LH-DB-001": RuleDefinition(
        rule_id="LH-DB-001",
        title="Insecure PostgreSQL pg_hba.conf Rule or Unrestricted CIDR",
        severity=FindingSeverity.CRITICAL,
        category=ConfigCategory.AUTHENTICATION,
        engines=[DatabaseEngine.POSTGRESQL],
        description=(
            "PostgreSQL pg_hba.conf specifies 'trust' or cleartext 'password' authentication, "
            "or permits unrestricted remote access from 0.0.0.0/0 or ::/0."
        ),
        remediation=(
            "Use 'scram-sha-256' or 'cert' authentication and restrict client CIDRs to specific "
            "subnets."
        ),
    ),
    "LH-DB-002": RuleDefinition(
        rule_id="LH-DB-002",
        title="Database Server Bound to All Network Interfaces",
        severity=FindingSeverity.HIGH,
        category=ConfigCategory.NETWORK,
        engines=[
            DatabaseEngine.POSTGRESQL,
            DatabaseEngine.MYSQL,
            DatabaseEngine.REDIS,
            DatabaseEngine.MONGODB,
        ],
        description=(
            "Database daemon listens on all interfaces (listen_addresses='*', bind 0.0.0.0, "
            "net.bindIp: 0.0.0.0), exposing service to untrusted network traffic."
        ),
        remediation=(
            "Bind database servers strictly to localhost (127.0.0.1) or private VPC interfaces."
        ),
    ),
    "LH-DB-003": RuleDefinition(
        rule_id="LH-DB-003",
        title="Transport Encryption (SSL/TLS) Disabled or Not Enforced",
        severity=FindingSeverity.HIGH,
        category=ConfigCategory.ENCRYPTION,
        engines=[
            DatabaseEngine.POSTGRESQL,
            DatabaseEngine.MYSQL,
            DatabaseEngine.REDIS,
            DatabaseEngine.MONGODB,
        ],
        description=(
            "TLS transport encryption is disabled (ssl=off, require_secure_transport=OFF, "
            "net.tls.mode: disabled, or tls-port 0), transmitting data in cleartext."
        ),
        remediation=(
            "Enable TLS/SSL certificates and mandate encrypted connections for all clients."
        ),
    ),
    "LH-DB-004": RuleDefinition(
        rule_id="LH-DB-004",
        title="Authentication Bypass or Authorization Disabled",
        severity=FindingSeverity.CRITICAL,
        category=ConfigCategory.AUTHENTICATION,
        engines=[DatabaseEngine.MYSQL, DatabaseEngine.MONGODB, DatabaseEngine.REDIS],
        description=(
            "Database authentication or authorization checks are bypassed (skip-grant-tables "
            "in MySQL, security.authorization: disabled in MongoDB, or missing requirepass)."
        ),
        remediation=(
            "Ensure authentication is enforced; never deploy skip-grant-tables or disabled auth."
        ),
    ),
    "LH-DB-005": RuleDefinition(
        rule_id="LH-DB-005",
        title="Arbitrary Local or Server File Access Enabled",
        severity=FindingSeverity.HIGH,
        category=ConfigCategory.FILE_ACCESS,
        engines=[DatabaseEngine.MYSQL],
        description=(
            "MySQL enables LOAD DATA LOCAL INFILE (local_infile=1) or configures an unrestricted "
            "or empty secure_file_priv, allowing arbitrary file reading or writing."
        ),
        remediation=(
            "Set local_infile = 0 and specify a restricted directory for secure_file_priv."
        ),
    ),
    "LH-DB-006": RuleDefinition(
        rule_id="LH-DB-006",
        title="Dangerous Redis Commands Enabled or Protected-Mode Disabled",
        severity=FindingSeverity.HIGH,
        category=ConfigCategory.COMMANDS,
        engines=[DatabaseEngine.REDIS],
        description=(
            "Dangerous Redis administrative commands (FLUSHALL, FLUSHDB, CONFIG, EVAL, SHUTDOWN) "
            "are not renamed/disabled, or protected-mode is explicitly set to 'no'."
        ),
        remediation=(
            "Disable dangerous commands with 'rename-command <CMD> \"\"' and set protected-mode."
        ),
    ),
    "LH-DB-007": RuleDefinition(
        rule_id="LH-DB-007",
        title="MongoDB Server-Side JavaScript or Legacy HTTP Interface Enabled",
        severity=FindingSeverity.HIGH,
        category=ConfigCategory.FILE_ACCESS,
        engines=[DatabaseEngine.MONGODB],
        description=(
            "MongoDB has server-side JavaScript execution enabled (security.javascriptEnabled) "
            "or enables obsolete HTTP status/REST interfaces (net.http.enabled: true)."
        ),
        remediation=(
            "Disable server-side JavaScript (javascriptEnabled: false) and HTTP web interfaces."
        ),
    ),
    "LH-DB-008": RuleDefinition(
        rule_id="LH-DB-008",
        title="Weak Password Hashing Algorithm Configured",
        severity=FindingSeverity.MEDIUM,
        category=ConfigCategory.AUTHENTICATION,
        engines=[DatabaseEngine.POSTGRESQL, DatabaseEngine.MYSQL],
        description=(
            "Database utilizes obsolete or weak hashing algorithms (MD5 in PostgreSQL or "
            "mysql_native_password in MySQL) instead of SCRAM-SHA-256 or caching_sha2_password."
        ),
        remediation=(
            "Set password_encryption = 'scram-sha-256' in PostgreSQL and "
            "default_authentication_plugin = 'caching_sha2_password' in MySQL."
        ),
    ),
    "LH-DB-009": RuleDefinition(
        rule_id="LH-DB-009",
        title="Missing Connection, Disconnection, or Audit Logging",
        severity=FindingSeverity.MEDIUM,
        category=ConfigCategory.LOGGING,
        engines=[
            DatabaseEngine.POSTGRESQL,
            DatabaseEngine.MYSQL,
            DatabaseEngine.REDIS,
            DatabaseEngine.MONGODB,
        ],
        description=(
            "Database audit logging is absent or disabled (log_connections=off, "
            "log_disconnections=off, log_statement=none, or missing auditLog in MongoDB)."
        ),
        remediation=(
            "Enable connection and statement auditing logs to record security-relevant events."
        ),
    ),
    "LH-DB-010": RuleDefinition(
        rule_id="LH-DB-010",
        title="Hardcoded Plaintext Passwords or Replication Secrets in Config",
        severity=FindingSeverity.CRITICAL,
        category=ConfigCategory.SECRETS,
        engines=[
            DatabaseEngine.POSTGRESQL,
            DatabaseEngine.MYSQL,
            DatabaseEngine.REDIS,
            DatabaseEngine.MONGODB,
        ],
        description=(
            "Database configuration file stores static plaintext authentication credentials, "
            "passwords, or replication tokens (requirepass, masterauth, master-password)."
        ),
        remediation=(
            "Externalize secrets into environment variables, file inclusion paths, or vaults."
        ),
    ),
}
