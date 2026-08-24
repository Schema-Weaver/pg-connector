# @vivekmind/pg-connector

> **Bridge between the Schema Weaver browser IDE and your PostgreSQL databases.**
> Runs near the DB. Never exposes credentials. Executes queries and migrations on demand.

[![npm version](https://img.shields.io/npm/v/@vivekmind/pg-connector.svg)](https://www.npmjs.com/package/@vivekmind/pg-connector)
[![license](https://img.shields.io/npm/l/@vivekmind/pg-connector.svg)](./LICENSE)
[![node version](https://img.shields.io/node/v/@vivekmind/pg-connector.svg)](https://nodejs.org)

## What is Schema Weaver?

[Schema Weaver](https://schemaweaver.vivekmind.com) is a PostgreSQL schema management SaaS that helps teams visualize, edit, and migrate their database schemas from a browser-based IDE. SW Agent is the on-premises bridge that connects that IDE to your actual databases—without ever exposing credentials to the cloud.

## What SW Agent Does

SW Agent is a lightweight daemon that:

- **Runs near your database** — on your laptop, an EC2 instance, or a bastion host in your VPC
- **Holds DB credentials locally** — never sends connection strings to the cloud
- **Enforces per-user permissions** — 4 permission levels × 4 roles
- **Executes queries & migrations** — on demand from the browser IDE
- **Streams results efficiently** — chunked for large datasets (100 rows / 64KB / 100ms)
- **Writes a tamper-evident audit log** — SHA-256 hash chain for compliance

## Architecture

```
┌────────────────┐                    ┌────────────────┐                    ┌────────────────┐
│     Browser    │      WSS           │   Cloud User   │      WSS          │    SW Agent    │
│  (Schema       │◄──────────────────►│    Gateway     │◄──────────────────►│   (this pkg)   │
│   Weaver IDE)  │  www.worker-pod.io │                │                    │                │
└────────────────┘                    └────────────────┘                    └───────┬────────┘
                                                                                    │
                                                                          PostgreSQL │
                                                                                    │
                                                                           pg        ▼
                                                                           ┌────────────────┐
                                                                           │    Postgres    │
                                                                           │    Database   │
                                                                           └────────────────┘
                                                                                   
                                                                                   ┌────────────────┐
                                                                                   │   Audit Log    │
                                                                                   │ (JSONL + hash  │
                                                                                   │    chain)      │
                                                                                   └────────────────┘
```

The agent connects **outbound** to the cloud gateway — no inbound firewall changes required.

## Install

### As a CLI (run the agent daemon)

```bash
npm install -g @vivekmind/pg-connector

# Or use without installing:
npx @vivekmind/pg-connector init
```

### As a library (programmatic API)

```bash
npm install @vivekmind/pg-connector
```

### On EC2 / Ubuntu / VPC (Linux)

```bash
# Install globally
sudo npm install -g @vivekmind/pg-connector

# Initialize
schemaweaver init

# Add your database
schemaweaver db add

# Start as foreground process
schemaweaver agent start

# Or generate a systemd service for 24/7 background operation
node $(npm root -g)/@vivekmind/pg-connector/scripts/generate-systemd-service.mjs \
  --user ubuntu --output ./schemaweaver.service
sudo cp schemaweaver.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now schemaweaver
```

> **CLI aliases**: After global install, you can use any of: `schemaweaver`, `sw-agent`, `@vivekmind/pg-connector`, or `db-connector`.

### Migrating from `@vivekmind/sw-agent`

```bash
# Uninstall old package
npm uninstall -g @vivekmind/sw-agent

# Install new package (config in ~/.sw-agent is preserved)
npm install -g @vivekmind/pg-connector
```

## Quick Start (CLI)

```bash
# 1. Initialize the agent on your machine
sw-agent init
#  ✓ Machine label: my-laptop
#  ✓ Cloud URL: wss://agent.schema-weaver.dev
#  ✓ Permission: auto_upgrade
#  ✓ Agent ID: agt_v3_5556c36b
#  Token shown once — keep it safe to link browser projects.

# 2. Add a PostgreSQL database (interactive, with connection test)
sw-agent db add
#  ? Project name: myapp
#  ? Database alias: myapp-db
#  ? Host: localhost
#  ? Port: 5432
#  ? Database name: myapp
#  ? Username: myapp_user
#  ? Password storage: Environment variable
#  ? Environment variable name: DB_PASSWORD
#  ? SSL mode: require
#  ✓ Connected. PostgreSQL 16.3
#  ✓ Database added successfully!

# 3. List your databases
sw-agent db list
#  ┌────────┬─────────┬──────────────────┬──────────┬─────────┬────────┬─────┬──────────┐
#  │ ALIAS  │ PROJECT │ HOST             │ DATABASE │ USER    │ SSL    │ PWD │ PERM     │
#  ├────────┼─────────┼──────────────────┼──────────┼─────────┼────────┼─────┼──────────┤
#  │ myapp- │ myapp   │ localhost:5432   │ myapp    │ myapp_u │ require│ env │ default  │
#  │ db     │         │                  │          │ ser     │        │     │          │
#  └────────┴─────────┴──────────────────┴──────────┴─────────┴────────┴─────┴──────────┘

# 4. Test a connection
sw-agent db test myapp-db
#  ✓ Connected in 12ms
#    PostgreSQL 16.3
#    Database: myapp
#    User: myapp_user
#    Latency: 12ms

# 5. Verify everything works
sw-agent doctor
#  ✓ SW Agent directory exists
#  ✓ Machine config valid         Agent ID: agt_v3_5556c36b
#  ✓ Token format
#  ⚠ Databases config valid       No databases configured
#  ⚠ Databases reachable          No databases configured to test
#  ✓ Audit directory writable
#  ✓ Disk space                   Skipped (platform check)
#  ✓ Node version                 v24.15.0
#  ✓ PID file                     No PID file (agent not running)

# 6. Start the agent daemon
sw-agent agent start
#  Starting SW Agent
#    Agent ID: agt_v3_5556c36b
#    Cloud:    wss://agent.schema-weaver.dev
#    Databases: 1

# 7. Check status
sw-agent agent status
#  Agent Status
#    Running          Yes
#    PID              12345
#    Version          0.1.2
#    Started          2025-01-15 10:23:00
#    Uptime           2h 34m
#    Last heartbeat   2025-01-15 12:57:00
#    Status           ✓ OK
#  Channels
#    SSE              connected
#    WSS              idle
#  Stats
#    Queries served   42
#    Streams served   5
#    Migrations run   3
#    ...
```

## Quick Start (Programmatic)

```typescript
import { AgentClient } from '@vivekmind/pg-connector';

const client = new AgentClient({
  relayUrl: 'wss://www.worker-pod.io',
  agentId: 'agt_laptop_a1b2c3d4',
  token: 'swagt_7Kk2mP9xQr4T...',
});

await client.connect();

const ctx = { project: 'myapp', role: 'admin' as const, userId: 'alice' };

// Run a query
const result = await client.query('SELECT * FROM users LIMIT 10', ctx);
console.log(result.rows);

// Stream a large result
for await (const chunk of client.streamQuery('SELECT * FROM big_table', ctx)) {
  console.log(`Chunk ${chunk.chunkIndex}: ${chunk.rows.length} rows`);
}

// Run a migration
const migration = await client.migrate(
  'CREATE TABLE foo (id serial PRIMARY KEY);',
  ctx,
  { strategy: 'single_tx' }
);

// Introspect the schema
const schema = await client.introspect(ctx);
console.log(schema.tables);

await client.disconnect();
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `sw-agent init` | Initialize agent on this machine (generate ID + token) |
| `sw-agent db add` | Add a PostgreSQL database (interactive, with connection test) |
| `sw-agent db list` | List configured databases (pretty table) |
| `sw-agent db remove <alias>` | Remove a database entry |
| `sw-agent db test <alias>` | Test database connection (with latency) |
| `sw-agent db edit <alias>` | Edit a database entry (interactive) |
| `sw-agent project list` | List all linked projects |
| `sw-agent agent start` | Start agent daemon (foreground) |
| `sw-agent agent start --daemon` | Start as background daemon |
| `sw-agent agent stop` | Stop running agent (cleans up PID file) |
| `sw-agent agent stop --force` | Force kill (SIGKILL) |
| `sw-agent agent status` | Show daemon health and stats |
| `sw-agent doctor` | Run pre-flight diagnostic checks (includes DB reachability) |
| `sw-agent logs` | View/filter the audit log |
| `sw-agent logs --follow` | Follow audit log in real-time |
| `sw-agent audit verify` | Verify audit log hash chain integrity |
| `sw-agent link <project>` | Link to a browser project |

## Permission Model

Each project has a **permission level**:

| Level | Behavior |
|-------|----------|
| `read_only` | Only SELECT queries allowed |
| `auto_upgrade` | Reads + pre-registered migrations auto-approved |
| `manual` | Every query/migration requires browser approval |
| `full` | All queries and migrations auto-approved |

Each request is stamped with a **role** from the browser:

| Role | query | write | migrate | cancel | introspect |
|------|-------|-------|---------|--------|------------|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `developer` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `data_reader` | ✓ | ✗ | ✗ | ✓ | ✓ |
| `viewer` | ✓ | ✗ | ✗ | ✗ | ✓ |

## Audit Log

Every action is logged to `~/.sw-agent/audit/audit.jsonl` with a SHA-256 hash chain:

```bash
# View recent events
sw-agent logs --limit 20

# Filter by user
sw-agent logs --user alice

# Verify chain integrity
sw-agent audit:verify
# ✓ Verified 1,247 entries, chain intact
```

Each entry includes: timestamp, user, role, action, decision (allow/deny), outcome, SQL fingerprint, and duration.

## Interactive REPL

Running `sw-agent` with no arguments launches an interactive REPL with tab completion:

```bash
$ sw-agent

  ╔══════════════════════════════════════════════════╗
  ║                                                  ║
  ║    Schema Weaver Agent    v0.1.1                ║
  ║                                                  ║
  ║    Bridge between your browser IDE and PG.       ║
  ║                                                  ║
  ╚══════════════════════════════════════════════════╝

  Agent ID:  agt_v3_5556c36b  ✓ running
  Config:    ~/.sw-agent

  Type help for commands, exit to quit.

sw-agent › help
  Commands:
    init              First-time setup
    status            Agent status
    doctor            Diagnostics
    db add            Add database
    db ls             List databases
    db remove         Remove database
    db test           Test connection
    db edit           Edit database
    projects          Linked projects
    link              Link project
    start             Start daemon
    stop              Stop daemon
    logs              Audit logs
    audit verify      Verify audit chain
    config show       Show config
    help              Show help
    clear             Clear screen
    exit              Quit

sw-agent › 
```

## Modern UI Features

The CLI uses a modern terminal UI inspired by Vite, Claude Code, and Cargo:

- **Green checkmarks (✓)** for success states
- **Red crosses (✗)** for errors
- **Yellow warnings (⚠)** for warnings
- **Animated spinner** for long-running operations (connection tests, audit verification)
- **Pretty tables** with Unicode box drawing for database lists and status output
- **Cyan brand accents** for links and commands
- **Dim gray** for metadata and timestamps
- **Password masking** with `•` dots in interactive prompts
- **Tab completion** in the REPL

Files live in `~/.sw-agent/` with `0600` permissions:

| File | Description |
|------|-------------|
| `sw-agent.config.json` | Machine config (agent_id, token, version) |
| `databases.config.json` | Registered databases (one per project) |
| `audit/audit.jsonl` | Tamper-evident audit log |
| `agent.pid` | Daemon PID file (runtime) |
| `agent.status.json` | Daemon health (runtime) |

## Features

- **Query execution** — Run SQL with automatic timeout and cancellation
- **Streaming** — Chunked results for large datasets (async iterable)
- **Migrations** — Single-transaction or per-statement strategies
- **Advisory locks** — Prevent concurrent migrations on the same DB
- **Schema introspection** — List tables, columns, indexes, constraints
- **Query cancellation** — In-flight queries can be cancelled via control channel
- **Manual approval flow** — Browser prompts for sensitive operations
- **Auto-upgrade** — Pre-register migration plans for auto-approval
- **Mock relay** — Built-in development relay for local testing

## Development

```bash
cd sw-agent

# Install dependencies
npm install

# Build
npm run build

# Type check
npm run typecheck

# Lint
npm run lint

# Run unit tests
npm test

# Run E2E tests (requires PostgreSQL)
TEST_PG_URL=postgresql://localhost:5432/test npm run test:e2e
```

## API Exports

### `@vivekmind/pg-connector` (Client SDK)

Browser-safe exports for connecting to agents:

```typescript
export { AgentClient } from '@vivekmind/pg-connector';
export { AgentClientError, AgentClientTimeoutError, AgentClientDisconnectedError } from '@vivekmind/pg-connector';
export { MessageType, ErrorCode } from '@vivekmind/pg-connector';
```

### `@vivekmind/pg-connector` (Server Runtime)

Full exports including PostgreSQL execution:

```typescript
// Config
export { loadMachineConfig, saveMachineConfig } from '@vivekmind/pg-connector';
export { loadDatabaseConfig, saveDatabaseConfig, getDatabase } from '@vivekmind/pg-connector';

// Protocol
export { MessageType, ErrorCode, createMessage, serialize, deserialize } from '@vivekmind/pg-connector';

// Execution
export { PoolManager, QueryRunner, MigrationRunner, Introspector, Canceller } from '@vivekmind/pg-connector';

// Permissions
export { PermissionChecker, AutoUpgradeChecker, ManualApprovalHandler, PlanRegistry } from '@vivekmind/pg-connector';

// Audit
export { AuditSink, LocalAuditWriter, CloudAuditWriter, verifyChain } from '@vivekmind/pg-connector';

// Channels
export { AgentSession, WakeChannel, DataChannel } from '@vivekmind/pg-connector';
```

## Test Coverage

- **240+ tests** across protocol, channels, execution, permissions, audit, and CLI
- **E2E tests** for full agent ↔ relay ↔ client flows
- **Mock relay** for isolated testing

## Related

- [Schema Weaver](https://schemaweaver.vivekmind.com) — Main product
- [GitHub](https://github.com/Schema-Weaver/@vivekmind/pg-connector) — Source code
- [Security Policy](./SECURITY.md) — Vulnerability disclosure & threat model
- [Code of Conduct](./CODE_OF_CONDUCT.md) — Community guidelines

## License

MIT © 2026 Schema Weaver
