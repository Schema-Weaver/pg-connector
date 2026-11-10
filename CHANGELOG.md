# Changelog

All notable changes to `@schema-weaver/pg-connector` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.3] - 2026-11-10

### Changed

- **Database-Centric Routing & Resolution**: Decoupled database lookup and routing from the legacy `project` parameter. Requests now resolve primarily by `db_alias`.
- **Multi-Database Support**: Removed the artificial "one database per project" constraint in `db add` and config validation. Users can now register multiple databases cleanly under distinct aliases on a single connector agent.
- **Resilient Default Fallback**: Inbound relay frames carrying `default` database alias or missing project parameters now seamlessly fall back to the registered database, preventing false `database_not_found` denials in the Data Explorer and IDE.

## [2.0.2] - 2026-11-05

### Fixed

- **Headless Linux & EC2 Clipboard Support**: Prevent CLI initialization crash (`spawn xclip ENOENT`) on headless systems. Added automatic display detection (`isHeadlessLinux`), pre-execution binary PATH validation (`isCommandAvailable`), multi-platform utility support (`clip`, `pbcopy`, `wl-copy`, `xclip`, `xsel`), and graceful fallback to manual token copying.
- **Initialization Error Resilience**: Wrapped clipboard execution in a non-blocking safe block, ensuring token generation, configuration persistence, and service startup continue uninterrupted even if clipboard operations fail.

## [2.0.1] - 2026-10-09

### Changed

- **Rate Limiting**: Increased concurrency and burst limits for seamless data exploration in browser IDE.
- **Permissions & Security**: Permitted read-only catalog functions, improved session wake recovery, and aligned auth headers.

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

[2.0.2]: https://github.com/Schema-Weaver/pg-connector/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/Schema-Weaver/pg-connector/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Schema-Weaver/pg-connector/releases/tag/v2.0.0
