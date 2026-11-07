# ==============================================================================
# Product:       lh-db-auditor (lh-db)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Pytest test configuration and fixtures for lh-db-auditor.

Provides hardened and insecure database configuration fixtures across
PostgreSQL, MySQL, Redis, and MongoDB engines.
"""

from __future__ import annotations

from pathlib import Path

import pytest

CLEAN_POSTGRESQL_CONF = """
# PostgreSQL Configuration (Hardened)
listen_addresses = '127.0.0.1,10.0.0.5'
ssl = on
password_encryption = 'scram-sha-256'
log_connections = on
log_disconnections = on
log_statement = 'ddl'
"""

CLEAN_PG_HBA_CONF = """
# PostgreSQL pg_hba.conf (Hardened)
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
hostssl all             all             192.168.1.0/24          scram-sha-256
hostssl all             all             10.0.0.0/8              scram-sha-256
"""

CLEAN_MYSQL_CNF = """
# MySQL Configuration (Hardened)
[mysqld]
bind-address = 127.0.0.1
require_secure_transport = ON
local_infile = 0
secure_file_priv = /var/lib/mysql-files
default_authentication_plugin = caching_sha2_password
general_log = ON
"""

CLEAN_REDIS_CONF = """
# Redis Configuration (Hardened)
bind 127.0.0.1
port 0
tls-port 6379
protected-mode yes
requirepass ${REDIS_PASS_ENV}
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command EVAL ""
rename-command SHUTDOWN ""
rename-command DEBUG ""
"""

CLEAN_MONGOD_CONF = """
# MongoDB Configuration (Hardened)
net:
  port: 27017
  bindIp: 127.0.0.1
  tls:
    mode: requireTLS
security:
  authorization: enabled
  javascriptEnabled: false
auditLog:
  destination: file
  format: JSON
  path: /var/log/mongodb/audit.json
"""

VULNERABLE_PG_HBA_CONF = """
# Vulnerable pg_hba.conf
host all all 0.0.0.0/0 trust
host all all 10.0.0.0/8 password
host all all 192.168.1.0/24 md5
"""

VULNERABLE_POSTGRESQL_CONF = """
# Vulnerable postgresql.conf
listen_addresses = '*'
ssl = off
password_encryption = md5
log_connections = off
log_disconnections = off
log_statement = none
password = 'hardcoded_plaintext_secret'
"""

VULNERABLE_MYSQL_CNF = """
# Vulnerable my.cnf
[mysqld]
bind-address = 0.0.0.0
require_secure_transport = OFF
skip-grant-tables
local_infile = 1
secure_file_priv = ""
default_authentication_plugin = mysql_native_password
password = 'plaintext_mysql_secret'
"""

VULNERABLE_REDIS_CONF = """
# Vulnerable redis.conf
bind 0.0.0.0
port 6379
protected-mode no
requirepass hardcoded_redis_pwd
"""

VULNERABLE_MONGOD_CONF = """
# Vulnerable mongod.conf
net:
  bindIp: 0.0.0.0
  tls:
    mode: disabled
  http:
    enabled: true
security:
  authorization: disabled
  javascriptEnabled: true
"""


@pytest.fixture
def clean_postgres_files(tmp_path: Path) -> tuple[Path, Path]:
    """Provide temporary hardened postgresql.conf and pg_hba.conf files."""
    conf = tmp_path / "postgresql.conf"
    conf.write_text(CLEAN_POSTGRESQL_CONF.strip(), encoding="utf-8")
    hba = tmp_path / "pg_hba.conf"
    hba.write_text(CLEAN_PG_HBA_CONF.strip(), encoding="utf-8")
    return conf, hba


@pytest.fixture
def clean_mysql_file(tmp_path: Path) -> Path:
    """Provide temporary hardened my.cnf file."""
    cnf = tmp_path / "my.cnf"
    cnf.write_text(CLEAN_MYSQL_CNF.strip(), encoding="utf-8")
    return cnf


@pytest.fixture
def clean_redis_file(tmp_path: Path) -> Path:
    """Provide temporary hardened redis.conf file."""
    rconf = tmp_path / "redis.conf"
    rconf.write_text(CLEAN_REDIS_CONF.strip(), encoding="utf-8")
    return rconf


@pytest.fixture
def clean_mongod_file(tmp_path: Path) -> Path:
    """Provide temporary hardened mongod.conf file."""
    mconf = tmp_path / "mongod.conf"
    mconf.write_text(CLEAN_MONGOD_CONF.strip(), encoding="utf-8")
    return mconf


@pytest.fixture
def vulnerable_postgres_files(tmp_path: Path) -> tuple[Path, Path]:
    """Provide temporary vulnerable postgresql.conf and pg_hba.conf files."""
    conf = tmp_path / "postgresql.conf"
    conf.write_text(VULNERABLE_POSTGRESQL_CONF.strip(), encoding="utf-8")
    hba = tmp_path / "pg_hba.conf"
    hba.write_text(VULNERABLE_PG_HBA_CONF.strip(), encoding="utf-8")
    return conf, hba


@pytest.fixture
def vulnerable_mysql_file(tmp_path: Path) -> Path:
    """Provide temporary vulnerable my.cnf file."""
    cnf = tmp_path / "mysqld.cnf"
    cnf.write_text(VULNERABLE_MYSQL_CNF.strip(), encoding="utf-8")
    return cnf


@pytest.fixture
def vulnerable_redis_file(tmp_path: Path) -> Path:
    """Provide temporary vulnerable redis.conf file."""
    rconf = tmp_path / "redis.conf"
    rconf.write_text(VULNERABLE_REDIS_CONF.strip(), encoding="utf-8")
    return rconf


@pytest.fixture
def vulnerable_mongod_file(tmp_path: Path) -> Path:
    """Provide temporary vulnerable mongod.conf file."""
    mconf = tmp_path / "mongod.conf"
    mconf.write_text(VULNERABLE_MONGOD_CONF.strip(), encoding="utf-8")
    return mconf
