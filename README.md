# lh-db-auditor

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-db-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-db-auditor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise database configuration & access security developed by **Logihertz Systems (OPC) Private Limited**.

Audits PostgreSQL (postgresql.conf, pg_hba.conf), MySQL (my.cnf), Redis (redis.conf), and MongoDB (mongod.cfg) configurations for trust authentication, disabled TLS, wildcard bind addresses, and missing audit logs.

---

## Key Features

- **Multi-Database Engine Support**: Native parsers for PostgreSQL, MySQL, MongoDB, and Redis without requiring live database connections.
- **Network Binding Exposure**: Flags database services listening on `0.0.0.0`, `::`, or public interfaces instead of localhost/private network.
- **Authentication Method Auditing**: Detects insecure `trust` or plaintext `password` authentication rules in `pg_hba.conf`.
- **Encryption in Transit**: Audits TLS/SSL enforcement flags and flags disabled SSL or self-signed certificate configs.
- **Audit Logging & Monitoring**: Verifies query logging, connection logging, and duration threshold configuration.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-DB-001` | `CRITICAL` | Database service bound to wildcard address (0.0.0.0 or ::) exposing port to public network |
| `LH-DB-002` | `CRITICAL` | Insecure authentication method configured (pg_hba.conf 'trust' or plaintext password) |
| `LH-DB-003` | `CRITICAL` | TLS/SSL encryption disabled on database listener (ssl = off) |
| `LH-DB-004` | `HIGH` | Redis instance configured with requirepass disabled or empty password |
| `LH-DB-005` | `HIGH` | MongoDB running with authorization: disabled or no security auth enabled |
| `LH-DB-006` | `HIGH` | Dangerous MySQL options enabled (local-infile = 1, skip-grant-tables, or symbolic-links = 1) |
| `LH-DB-007` | `MEDIUM` | Audit logging or query statement logging disabled (log_statement = none) |
| `LH-DB-008` | `MEDIUM` | Default database administration port configured without custom obfuscation |
| `LH-DB-009` | `HIGH` | Excessive or unlimited connection limits configured without resource throttling |
| `LH-DB-010` | `LOW` | Missing connection timeout or idle transaction timeout configuration |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-db-auditor.git
cd lh-db-auditor

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-db` (also accessible via `lh-db`, `lh-db-auditor`).

```bash
# Audit a PostgreSQL configuration directory
lh-db scan /etc/postgresql/15/main/

# Audit a Redis configuration file
lh-db scan /etc/redis/redis.conf --format json

# Export findings to OASIS SARIF v2.1.0
lh-db scan ./db-configs/ --format sarif --output db-findings.sarif

# List all detection rules
lh-db rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
