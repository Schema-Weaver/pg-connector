# Changelog

All notable changes to `@schema-weaver/pg-connector` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-08

### Added

- **Local Credential Boundary (LCB)**: Database credentials remain strictly on-premises in encrypted configuration (`databases.config.json` via AES-256-GCM under a scrypt-derived key). Passwords never leave your environment.
- **Connector-Enforced Read-Only Execution (CERO)**: Local AST-based SQL classification and parsing via PostgreSQL's parser (`libpg_query`), enforcing read-only guarantees and role capabilities independent of cloud claims.
- **Outbound-Only Networking**: Initiates outbound TLS connections (SSE wake channel + WSS data streaming) to the Schema Weaver Cloud Relay with zero open inbound ports.
- **Role-Based Access Control (RBAC)**: Fine-grained permission model (`read_only`, `auto_upgrade`, `manual`, `full`) across roles (`admin`, `developer`, `data_reader`, `viewer`).
- **Cryptographic Audit Log**: Tamper-evident monotonic HMAC-SHA256 hash-chained local audit log (`audit.jsonl`) with anchored head, verifiable via `pg-connector audit verify`.
- **Transient Data Streaming**: Ephemeral in-memory streaming of query results directly to the browser session over TLS WebSockets with zero disk caching or cloud persistence.
- **CLI Suite**: Full command-line interface (`pg-connector` / `sw-agent` / `schemaweaver`) with interactive REPL, database management (`db add`, `db list`, `db test`, `db query`, `db connect`), daemon lifecycle (`start`, `stop`, `status`), and diagnostic tools (`doctor`, `debug`).
- **Programmatic SDK**: Fully typed Node.js/TypeScript exports for `PoolManager`, `QueryRunner`, `MigrationRunner`, `AgentSession`, and `Dispatcher`.

[2.0.0]: https://github.com/Schema-Weaver/pg-connector/releases/tag/v2.0.0