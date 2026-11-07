# Security Rules Reference: lh-db-auditor

An enterprise enterprise database security posture auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-db-auditor`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-DB-001` | `CRITICAL` | Network Exposure | Database Bound to Wildcard Address (0.0.0.0 or ::) |
| `LH-DB-002` | `CRITICAL` | Authentication | Insecure Authentication Method Configured |
| `LH-DB-003` | `CRITICAL` | Transport Security | TLS/SSL Encryption Disabled on Database Listener |
| `LH-DB-004` | `HIGH` | Authentication | Redis Instance Configured with requirepass Disabled |
| `LH-DB-005` | `HIGH` | Authentication | MongoDB Running with Authorization Disabled |
| `LH-DB-006` | `HIGH` | Configuration Hygiene | Dangerous MySQL Options Enabled |
| `LH-DB-007` | `MEDIUM` | Audit Logging | Audit Logging or Query Statement Logging Disabled |
| `LH-DB-008` | `MEDIUM` | Network Hygiene | Default Database Administration Port Configured |
| `LH-DB-009` | `HIGH` | Availability | Excessive or Unlimited Connection Limits Configured |
| `LH-DB-010` | `LOW` | Session Management | Missing Connection Timeout or Idle Transaction Timeout |

---

## Granular Rule Specifications

### `LH-DB-001`: Database Bound to Wildcard Address (0.0.0.0 or ::)

- **Severity**: `CRITICAL`
- **Category**: `Network Exposure`
- **Description**: Database service listening on 0.0.0.0 or ::, exposing port directly to public networks.
- **Remediation**: Bind database listeners strictly to 127.0.0.1 or designated private subnet IP addresses.

---

### `LH-DB-002`: Insecure Authentication Method Configured

- **Severity**: `CRITICAL`
- **Category**: `Authentication`
- **Description**: PostgreSQL pg_hba.conf permits 'trust' or plaintext password authentication methods.
- **Remediation**: Enforce scram-sha-256 authentication for all remote and local PostgreSQL connections.

---

### `LH-DB-003`: TLS/SSL Encryption Disabled on Database Listener

- **Severity**: `CRITICAL`
- **Category**: `Transport Security`
- **Description**: Database service running with ssl = off or unencrypted transport allowed.
- **Remediation**: Enable TLS (ssl = on) and enforce client certificate validation (sslmode=verify-full).

---

### `LH-DB-004`: Redis Instance Configured with requirepass Disabled

- **Severity**: `HIGH`
- **Category**: `Authentication`
- **Description**: Redis server running without password authentication or with empty requirepass.
- **Remediation**: Configure strong requirepass passphrase or migrate to Redis ACL users with TLS.

---

### `LH-DB-005`: MongoDB Running with Authorization Disabled

- **Severity**: `HIGH`
- **Category**: `Authentication`
- **Description**: MongoDB instance running with security.authorization: disabled or missing auth block.
- **Remediation**: Enable security.authorization: enabled in mongod.conf to enforce authentication.

---

### `LH-DB-006`: Dangerous MySQL Options Enabled

- **Severity**: `HIGH`
- **Category**: `Configuration Hygiene`
- **Description**: MySQL configured with local-infile = 1, skip-grant-tables, or symbolic-links = 1.
- **Remediation**: Disable local-infile = 0, remove skip-grant-tables, and set symbolic-links = 0.

---

### `LH-DB-007`: Audit Logging or Query Statement Logging Disabled

- **Severity**: `MEDIUM`
- **Category**: `Audit Logging`
- **Description**: Database configured without statement logging or connection logging enabled.
- **Remediation**: Enable log_connections = on, log_disconnections = on, and log_statement = ddl in Postgres.

---

### `LH-DB-008`: Default Database Administration Port Configured

- **Severity**: `MEDIUM`
- **Category**: `Network Hygiene`
- **Description**: Database listening on standard well-known default port (5432, 3306, 6379, 27017).
- **Remediation**: Implement network isolation or port obfuscation to reduce automated perimeter scanning.

---

### `LH-DB-009`: Excessive or Unlimited Connection Limits Configured

- **Severity**: `HIGH`
- **Category**: `Availability`
- **Description**: Database max_connections set to excessive values without memory pooling limits.
- **Remediation**: Configure connection pooling (PgBouncer) and cap max_connections to hardware limits.

---

### `LH-DB-010`: Missing Connection Timeout or Idle Transaction Timeout

- **Severity**: `LOW`
- **Category**: `Session Management`
- **Description**: Database lacks idle_in_transaction_session_timeout or client timeout guardrails.
- **Remediation**: Set idle_in_transaction_session_timeout to terminate hung transactions automatically.

---
