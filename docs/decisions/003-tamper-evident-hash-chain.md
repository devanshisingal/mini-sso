# ADR 003: Tamper-Evident Audit Log via SHA-256 Cryptographic Hash Chaining

## Status
Accepted

## Context
Enterprise security audits and compliance frameworks (SOC 2, ISO 27001) require that authentication logs provide integrity and repudiation resistance. In typical web architectures, audit log entries are stored as plain rows in a relational database (`audit_log` table). If an insider or attacker gains database write access (e.g., via SQL injection or compromised credentials), they can modify, delete, or insert rows to conceal unauthorized access, and standard database backups cannot prove whether historical records were altered.

## Decision
We implemented a **cryptographic SHA-256 hash chain** across all audit log records:
1. Every audit entry contains two cryptographic hash columns:
   - `prev_hash`: The `entry_hash` of the immediately preceding record (or `"GENESIS"` for the very first log).
   - `entry_hash`: The SHA-256 digest computed over:
     `SHA256(prev_hash | normalized_utc_timestamp | user_id | client_id | event | outcome | ip | details)`
2. An administrative verification endpoint (`GET /admin/audit-log/verify`) recomputes the entire chain from Genesis to Head:
   - Verifies `record[i].prev_hash == record[i-1].entry_hash`.
   - Recomputes the entry hash and confirms `recomputed == record[i].entry_hash`.
   - Detects alterations, insertions, or deletions, reporting the exact `tampered_id` and violation type.

## Rationale
1. **Cryptographic Proof without Blockchain Overhead**: A linear hash chain provides Merkle-like integrity guarantees with trivial computational overhead ($O(N)$ SHA-256 calculations taking <10ms for thousands of rows) and no third-party dependencies or distributed consensus mechanisms.
2. **Immediate Tamper Detection**: If any row is altered (e.g. changing `outcome="failure"` to `"success"`), its `entry_hash` ceases to match. If an attacker re-computes `entry_hash`, the subsequent record's `prev_hash` is broken. An attacker would be forced to rewrite every subsequent record in the database—which would alter the published head hash.
3. **External Notarization**: The latest head hash can be periodically published to an external append-only medium (e.g., AWS CloudWatch Logs, an S3 Object Lock bucket, or Git commit tags), providing immutable non-repudiation.

## Consequences
- Requires strict timestamp normalization (`strftime("%Y-%m-%dT%H:%M:%S.%fZ")`) to ensure byte-exact deterministic hashing across diverse database engines (SQLite and PostgreSQL).
- Audit log writes require reading the latest head record hash before insertion, introducing minimal latency (~0.2ms).
