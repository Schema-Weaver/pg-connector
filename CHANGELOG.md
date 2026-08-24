# Changelog

All notable changes to @schema-weaver/agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-24

### Added

#### Core Infrastructure
- **Agent daemon** — Lightweight process that runs near your PostgreSQL database
- **Protocol layer** — JSON message envelope with typed requests/responses
- **WebSocket channels** — Wake channel (SSE) + data channel (WSS) for browser communication
- **Auto-reconnect** — Exponential backoff with jitter for resilient connections

#### CLI Commands
- `sw-agent init` — First-time setup (generates agent ID + authentication token)
- `sw-agent db:add` — Add a PostgreSQL database interactively
- `sw-agent db:ls` — List configured databases
- `sw-agent db:remove <alias>` — Remove a database entry
- `sw-agent db:test <alias>` — Test database connection
- `sw-agent ls:projects` — List all configured projects
- `sw-agent start` — Start agent daemon (foreground or background)
- `sw-agent stop` — Stop running agent
- `sw-agent status` — Show daemon health and stats
- `sw-agent logs` — View/filter audit log
- `sw-agent doctor` — Pre-flight diagnostic checks
- `sw-agent audit:verify` — Verify audit log hash chain integrity
- `sw-agent link <project>` — Link to a browser project

#### Query Execution
- **Query runner** — Execute single SQL statements with timeout enforcement
- **Streaming queries** — Chunked async iterables for large result sets
  - 100 rows per chunk, 64KB max, 100ms max interval
- **Query cancellation** — In-flight queries can be cancelled via control connection
- **Statement classification** — Detect read vs write vs DDL operations

#### Migration Engine
- **Single-transaction strategy** — All statements in one transaction, rollback on failure
- **Per-statement strategy** — Each statement in its own transaction
- **Advisory locks** — Prevent concurrent migrations on the same database
- **Non-transactional detection** — Handle PostgreSQL statements that can't run in a transaction

#### Permission System
- **4 permission levels** — `read_only`, `auto_upgrade`, `manual`, `full`
- **4 roles** — `admin`, `developer`, `data_reader`, `viewer`
- **Role-based access control** — Fine-grained capability checking per action
- **Manual approval flow** — Browser prompts for sensitive operations
- **Auto-upgrade** — Pre-register migration plans for automatic approval
- **Plan registry** — LRU cache for pre-approved migration SQL

#### Audit Logging
- **Local audit log** — JSONL file with SHA-256 hash chain
- **Tamper evidence** — Each entry links to previous via hash
- **Chain verification** — `audit:verify` command checks integrity
- **Query fingerprinting** — SHA-256 of SQL for log entries
- **Optional cloud sync** — Forward logs to Schema Weaver cloud (opt-in)

#### Schema Introspection
- **Table listing** — All tables with column definitions
- **Index inspection** — Indexes with columns and uniqueness
- **Constraint inspection** — Primary keys, foreign keys, unique constraints, checks
- **Column metadata** — Type, nullable, default value

#### Development Tools
- **Mock relay** — Built-in WebSocket relay for local testing
- **Doctor checks** — Validate Node version, config files, and database connections
- **Pid file management** — Track daemon process across restarts
- **Status file** — JSON health metrics updated every heartbeat

#### Testing
- **240+ tests** covering all modules
- **E2E test suite** — Full agent ↔ relay ↔ client flows
- **Test utilities** — Mock PostgreSQL, temp directories, fixture generators

### Security
- Credentials stored locally with `0600` file permissions
- Token-based authentication for browser connections
- No inbound ports required — agent connects outbound only
- Audit log provides full action history with user attribution

### Technical Details
- **Node.js 18+** — Uses native fetch, ESM modules
- **TypeScript 5.6+** — Full type safety
- **Zero runtime dependencies** for client SDK (except `ws` in Node)
- **PostgreSQL 12+** supported
- **ESM + CJS builds** — Works in all environments

---

## Future Roadmap

### [0.2.0] - Planned
- Cloud relay integration (production `sw-agent link`)
- Connection pooling metrics
- Query result caching
- Schema diff API

### [1.0.0] - Planned
- Stable API guarantees
- npm provenance signing
- Comprehensive docs site

---

[0.1.0]: https://github.com/Schema-Weaver/pg-connector/releases/tag/v0.1.0
