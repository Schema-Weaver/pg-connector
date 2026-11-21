# @schema-weaver/pg-connector · `sw-connector`

> **Secure Multi-Database Connector for Schema Weaver with Local Credential Boundary (LCB) and Connector-Enforced Read-Only Execution (CERO).**
> Connects local or VPC-hosted PostgreSQL, MySQL, and MongoDB databases to Schema Weaver. Database credentials never leave your environment.

[![npm version](https://img.shields.io/npm/v/@schema-weaver/pg-connector.svg)](https://www.npmjs.com/package/@schema-weaver/pg-connector)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node: >=18](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org)
[![TypeScript: 5+](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org)
[![Security: LCB + CERO](https://img.shields.io/badge/Security-LCB%20%2B%20CERO-purple.svg)](#security-architecture)

---

## What is `@schema-weaver/pg-connector`?

`@schema-weaver/pg-connector` (executable as `sw-connector`, `db-connector`, `pg-connector`, `sw-agent`, or `schemaweaver`) is a lightweight on-premises daemon and client library that links customer PostgreSQL, MySQL, and MongoDB databases with the [Schema Weaver](https://schemaweaver.dev) web platform (Data Explorer, SQL Editor, and Schema Migration Engine). `sw-connector` is the canonical binary name; the npm package keeps its original name so existing installs and upgrade paths are unchanged.

Unlike standard database connection proxies that store customer passwords and connection strings in cloud vaults, the Schema Weaver connector operates as a **customer-side execution and security boundary**.

---

## Core Architectural Principles

```text
                 SCHEMA WEAVER CLOUD
              ┌───────────────────────┐
              │ Cloud Orchestration   │
              │ Web Application UI    │
              │ Scoped Relay Plane    │
              │ Telemetry Storage     │
              └───────────┬───────────┘
                          │ Outbound TLS Only
                          │ (SSE Control + WSS Data)
                          ▼
             ┌────────────────────────────┐
             │ @schema-weaver/pg-connector│
             │  (Runs in Customer VPC)    │
             │                            │
             │  [LCB] Credentials Local   │
             │  [CERO] Policy Enforcement │
             │  [RAM] Ephemeral Streaming │
             └────────────┬───────────────┘
                          │ Local TCP / SSL Pool
                          ▼
                CUSTOMER DATABASE
        (PostgreSQL 12+, MySQL 8+, MongoDB 6+)
```

### 1. Local Credential Boundary (LCB)
Database host, port, username, password, connection strings, and SSL private keys **remain strictly inside your environment** in `~/.sw-agent/databases.config.json` (POSIX file mode `0o600`) or local OS environment variables. Passwords stored in that file are encrypted at rest with AES-256-GCM under a scrypt-derived key. The cloud control plane receives scoped identities (`agent_id`, `db_alias`, and `database` name) plus the query text, results, and schema needed to serve your session, carried over TLS (or over a loopback socket for a local development relay), and an active connection token hash: the agent sends `HMAC-SHA256(token, "sw-agent/relay-auth/v1")` rather than the token itself, so the long-lived secret never appears on the wire.

### 2. Connector-Enforced Read-Only Execution (CERO)
The connector acts as the final gatekeeper between external requests and your database engine:
- **Real PostgreSQL Parser**: Every PostgreSQL statement received from the cloud is parsed with PostgreSQL's own grammar (`libpg_query`) and classified from the resulting parse tree — not from a keyword guess. Multi-statement input is refused outright, and `SELECT … INTO`, `FOR UPDATE`, writable CTEs, and calls to privileged functions (`pg_read_file`, `lo_import`, `dblink_exec`, `setval`, …) are detected structurally. Classification is allowlist-based: only `SELECT` and `SHOW` are reads, and anything that fails to parse is denied.
- **MySQL Parser**: MySQL SQL is parsed with `node-sql-parser`'s MySQL dialect. Only `SELECT`, `DESCRIBE`, and `EXPLAIN` can be reads. A parse failure, a second statement, `SELECT … INTO OUTFILE` or `INTO @var`, `FOR UPDATE`/`LOCK IN SHARE MODE`, a `:=` assignment, an executable comment (`/*! … */` or `/*M! … */`, refused even inside a quoted run), or any function outside a built-in allow-list is refused. `SHOW`, `SET`, `CALL`, `PREPARE`, `LOAD DATA`, and all DDL are not reads.
- **MongoDB Allow-List**: MongoDB has no SQL grammar, so a command is a JSON document naming a collection and one of four read methods: `find`, `aggregate`, `count`, or `distinct`. There is deliberately no `runCommand` passthrough. Write stages (`$out`, `$merge`) and caller-supplied JavaScript (`$where`, `$function`, `$accumulator`) are rejected anywhere in a filter, pipeline, or option document, as are change streams and `system.*` collections.
- **PostgreSQL Verdict Before "Read"**: A PostgreSQL `SELECT` counts as a read only when every function it references is reported by `pg_proc` as `IMMUTABLE` and not `SECURITY DEFINER`. Anything else — volatile, stable, security-definer, or unresolvable — is escalated to the DDL capability requirement, so an operator-written function cannot be reached through a read. This is deliberately stricter than PostgreSQL's own guarantee: a `SELECT now()` needs the `ddl` capability.
- **Anti-Spoofing**: The browser's claimed `intent` is advisory only. If it disagrees with the parsed classification, the request is rejected — and no `intent` value grants an exemption.
- **Enforced by the database too**: For a `read_only` database PostgreSQL runs with `default_transaction_read_only = on` (a write raises `25006`); MySQL sets `SET SESSION TRANSACTION READ ONLY` and opens `START TRANSACTION READ ONLY` around every read (a write raises `1792`); MongoDB forces a read preference and read concern. Even a classifier miss cannot write through a read, and the connected database role remains the final authority. `sw-connector doctor` reports PostgreSQL role attributes, and the README's role guidance covers MySQL and MongoDB.
- **Role-Based Access Control**: Enforces 4 permission levels (`read_only`, `auto_upgrade`, `manual`, `full`) and role capabilities (`admin`, `developer`, `data_reader`, `viewer`) locally before touching the connection pool. The role arrives inside an envelope authenticated by the relay, and must fall within both the set negotiated for the session and this installation's `security.max_negotiable_role` ceiling (default `developer`).

### 3. Transient Data Plane
Query results are streamed in memory over TLS WebSocket connections directly to the browser session. Rows exist ephemerally in RAM buffers during transit; the connector **never writes them to disk**, and nothing in this package persists them to any cache or database.

### 4. Cryptographic Audit Log
Every operation (query, migration, schema introspection, cancellation) is recorded locally in `~/.sw-agent/audit/audit.jsonl` using a tamper-evident **HMAC-SHA256 cryptographic hash chain** with a monotonic sequence number and an anchored head. Each record names the database the request actually resolved to. Chain integrity is verifiable on demand with `sw-connector audit verify`.

---

## Installation

### Global CLI

```bash
# Install globally via npm
npm install -g @schema-weaver/pg-connector

# Or run directly without installation (Zero-Install):
npx @schema-weaver/pg-connector init
```

> **Available CLI binaries**: After global installation, `sw-connector`, `db-connector`, `pg-connector`, `sw-agent`, and `schemaweaver` can all be used interchangeably.

### As a Project Dependency

```bash
npm install @schema-weaver/pg-connector
```

---

## Quick Start (CLI Workflow)

### Step 1: Initialize the Connector

Initialize machine configuration and generate your connector token:

```bash
sw-connector init
```
```text
  Schema Weaver Agent — First Time Setup
  ──────────────────────────────────────────────────
  ✔ Machine label: production-bastion
  ✔ Cloud URL: wss://api.schemaweaver.dev
  ✔ Permission: read_only
  ✔ Log level: info

  ┌────────────────────────────────────────────────────┐
  │  Agent ID                                          │
  │  agt_prod-bastion_8f2b1a9c                         │
  └────────────────────────────────────────────────────┘
  ┌────────────────────────────────────────────────────┐
  │  Token (use this to link in web UI)               │
  │  swagt_9d8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b...        │
  └────────────────────────────────────────────────────┘
```

### Step 2: Attach a Database

#### Option A: Interactive Mode (with Live Connection Probe)
```bash
sw-connector db add
```
In an interactive terminal this opens a minimal full-screen wizard: **engine → optional connection URL → manual fields if needed → password source → SSL → (MongoDB-only settings) → permission → alias → review**. Leave the URL empty for manual entry. The alias is suggested from the database name near the end, and the project defaults to it. Use `↑`/`↓` or the mouse to move, `Enter` to continue, `1`-`9` to jump to a choice, `Esc` to go back, and `Ctrl+C` to cancel. A connection URL must not contain a password; the next step chooses an environment variable reference or a masked, encrypted-at-rest value.

In a piped or captured terminal, choice prompts use plain numbered input. Setting `SW_AGENT_NO_TUI=1` in a real terminal also skips the full-screen wizard and returns to the compact line prompts.

#### Option B: Non-Interactive via Connection URL
```bash
# The URL carries no password: a --url with a password is refused.
sw-connector db add \
  --url postgresql://app_user@localhost:5432/acme_prod \
  --alias acme-db \
  --project acme \
  --ssl verify-full \
  --password-stdin
```

#### Option C: Non-Interactive via Command-Line Flags
```bash
sw-connector db add \
  --alias analytics \
  --project warehouse \
  --host 10.0.1.20 \
  --port 5432 \
  --database analytics_prod \
  --user readonly_analyst \
  --env ANALYTICS_DB_PWD \
  --ssl verify-ca \
  --cert /etc/ssl/certs/rds-ca-2024.pem \
  --permission read_only
```

#### MySQL

```bash
sw-connector db add \
  --type mysql \
  --alias orders-db \
  --project orders \
  --host 10.0.1.30 \
  --port 3306 \
  --database orders_prod \
  --user sw_readonly \
  --env ORDERS_DB_PWD \
  --ssl verify-ca \
  --permission read_only
```

MySQL entries default to port `3306`. A `--url` with the `mysql://` scheme infers `--type mysql`; an explicit `--type` is authoritative. A password in the URL is refused, as for PostgreSQL.

#### MongoDB

```bash
sw-connector db add \
  --type mongodb \
  --alias events \
  --project analytics \
  --host cluster0.example.com \
  --database events \
  --user sw_reader \
  --env EVENTS_DB_PWD \
  --auth-source admin \
  --read-preference secondaryPreferred \
  --read-concern majority \
  --ssl require
```

MongoDB entries default to port `27017`. `--srv` builds a `mongodb+srv://` URI; with SRV the port is ignored because DNS supplies the hosts. MongoDB settings are stored field-by-field (`host`, `port`, `database`, `user`, password) rather than as a URI, so the password is encrypted under the credential key like every other engine. `--read-preference` accepts `primary`, `primaryPreferred`, `secondary`, `secondaryPreferred`, or `nearest`; `--read-concern` accepts `local`, `available`, `majority`, or `linearizable`. A `--url` with the `mongodb://` or `mongodb+srv://` scheme infers `--type mongodb`; an explicit `--type` is authoritative. The URL must not contain a password.

#### Password sources

`db add` refuses `--password` and `--pw`, and refuses a `--url` that carries a password: `process.argv` is readable by every local user. Supported channels, safest first:

| Channel | Notes |
| :--- | :--- |
| `SW_AGENT_DB_PASSWORD=<value> sw-connector db add …` | Read from the environment at run time |
| `--password-stdin` | Read from stdin |
| `--password-file <path>` | Must be mode `0600` and must not be a symlink |
| `--env <VAR>` | Stores only the variable **name**; the value is read at connect time |
| *(no flag)* | Masked interactive prompt |

> [!NOTE]
> `--ssl` accepts `disable`, `require`, `verify-ca` and `verify-full` for all three engines. New entries default to `require`, which is TLS without certificate verification — set it explicitly in any environment where the database hop is not fully trusted.

#### Configuration shape

`~/.sw-agent/databases.config.json` is a JSON array. `db_type` is optional and defaults to `postgres`, so entries written before the driver split load unchanged:

```json
[
  {
    "db_alias": "acme-db",
    "project_name": "acme",
    "db_type": "postgres",
    "host": "localhost",
    "port": 5432,
    "database": "acme_prod",
    "user": "readonly_analyst",
    "ssl_mode": "verify-full"
  },
  {
    "db_alias": "orders-db",
    "project_name": "orders",
    "db_type": "mysql",
    "host": "10.0.1.30",
    "port": 3306,
    "database": "orders_prod",
    "user": "sw_readonly",
    "ssl_mode": "verify-ca"
  },
  {
    "db_alias": "events",
    "project_name": "analytics",
    "db_type": "mongodb",
    "host": "cluster0.example.com",
    "port": 27017,
    "database": "events",
    "user": "sw_reader",
    "srv": false,
    "auth_source": "admin",
    "read_preference": "secondaryPreferred",
    "read_concern": "majority",
    "ssl_mode": "require"
  }
]
```

Passwords are not shown above: `db add` stores them encrypted as `password_stored`, or records only the environment variable name in `password_env`. `db show <alias>` redacts the secret; `db show <alias> --json` does too.

### Step 3: Test & Inspect Connections

```bash
# Fast reachability ping
sw-connector db ping acme-db

# Full connection test with latency measurement
sw-connector db test acme-db

# Multi-step deep diagnostics (network, catalog, permissions, timeouts)
sw-connector db test acme-db --detailed

# Detailed configuration and connection inspection
sw-connector db show acme-db

# Execute a quick query directly from the terminal
sw-connector db query acme-db "SELECT current_database(), version();"

# Launch an interactive database console session
sw-connector db connect acme-db
```

#### MongoDB query format

MongoDB is not queried with SQL. `db query`, the daemon's data channel, and the SQL Editor carry a MongoDB command as a JSON string:

```bash
sw-connector db query events \
  '{"collection":"events","method":"find","filter":{"type":"login"},"options":{"limit":50,"sort":{"created_at":-1}}}'
```

| Method | Required fields | Optional fields | Permitted `options` keys |
| :--- | :--- | :--- | :--- |
| `find` | `collection`, `method` | `filter` | `limit`, `skip`, `sort`, `projection`, `maxTimeMS`, `hint`, `collation`, `comment`, `batchSize` |
| `aggregate` | `collection`, `method`, `pipeline` | — | `maxTimeMS`, `allowDiskUse` (must be `false`), `batchSize`, `collation`, `hint`, `comment` |
| `count` | `collection`, `method` | `filter` | `limit`, `skip`, `maxTimeMS`, `hint`, `collation`, `comment` |
| `distinct` | `collection`, `method`, `field` | `filter` | `maxTimeMS`, `collation`, `comment` |

Top-level keys are limited to `collection`, `method`, `filter`, `pipeline`, `field`, and `options`; any unknown key is refused. There is no generic `runCommand` method: an operation that is not one of the four methods above is rejected before a MongoDB client call is made.

### Step 4: Start the Background Daemon

```bash
# Foreground execution (great for testing or Docker containers)
sw-connector start

# Background daemon mode (standard server operation)
sw-connector start --daemon
```

### Step 5: Check Status & Health

```bash
sw-connector status
```
```text
  Schema Weaver Agent — Status
  ──────────────────────────────────────────────────
  Process:           running (PID 4821)
  Uptime:            4h 12m 35s
  Version:           2.0.4
  Agent ID:          agt_prod-bastion_8f2b1a9c
  Cloud URL:         wss://api.schemaweaver.dev
  Permission Level:  read_only

  Channels:
    Wake (SSE):      connected (heartbeat: 2s ago)
    Data (WSS):      idle (pool ready)

  Databases (1):
    • acme-db        acme_prod (localhost:5432) — healthy
```

### Step 6: Link to Schema Weaver Cloud Web UI

1. Open [Schema Weaver Data Explorer](https://schemaweaver.dev).
2. Open the **Connect Database** modal.
3. Paste your **Agent ID** (`agt_...`) and **Token** (`swagt_...`).
4. The cloud pairs immediately with your daemon. All database operations are now routed through your local connector.

### Local development relay

To test against a backend running on this machine instead of the hosted relay:

```bash
sw-connector config set cloud_url ws://localhost:3000
sw-connector start --foreground
```

`ws://` is accepted **only** for a loopback host (`localhost`, `127.0.0.1`, other `127.0.0.0/8` addresses, or `::1`). Every remote relay still requires `wss://`; a remote `ws://` or `http://` URL is refused because the agent token is a permanent bearer credential. The audit ingest base is derived from the same URL, so it becomes `http://localhost:3000` for this setup. The agent still needs a token that the target backend recognises — use the pairing step above with your local UI if this token has not been registered there.

Restore the hosted relay with:

```bash
sw-connector config set cloud_url wss://api.schemaweaver.dev
```

---

## Complete CLI Command Reference

### Database Management (`db`)

| Command | Description |
| :--- | :--- |
| `sw-connector db add` | Add a database. `--type postgres\|mysql\|mongodb` selects the engine; without it, the engine is inferred from a `--url` scheme (`postgres://`, `postgresql://`, `mysql://`, `mongodb://`, `mongodb+srv://`) and otherwise defaults to `postgres`. Passwords come from the masked prompt, `--password-stdin`, `--password-file`, `--env <VAR>` or `SW_AGENT_DB_PASSWORD`; `--password`/`--pw` are refused. MongoDB adds `--srv`, `--auth-source`, `--read-preference`, and `--read-concern` |
| `sw-connector db list` (or `db ls`) | Display all configured databases in a formatted table, including engine type |
| `sw-connector db show <alias>` | Show detailed configuration and credentials mode for a database (`--json` supported). The password is always redacted |
| `sw-connector db edit <alias>` | Modify database settings, including `--type` and MongoDB fields (interactive or via flags: `--host`, `--port`, `--env`, etc.) |
| `sw-connector db test <alias>` | Test connection latency (`--detailed` for PostgreSQL deep diagnostics) |
| `sw-connector db ping <alias>` | Quick millisecond round-trip reachability ping |
| `sw-connector db query <alias> "<SQL\|JSON>"` | Execute a query and output tabular results. PostgreSQL/MySQL take SQL; MongoDB takes a JSON command |
| `sw-connector db connect <alias>` | Open an interactive query console using the same classification, timeout, and row caps. PostgreSQL offers `\dt`/`\dn`/`\l`; MySQL offers `SHOW TABLES`/`SHOW DATABASES`; MongoDB accepts JSON commands such as `{"collection":"users","method":"find"}` |
| `sw-connector db logs <alias>` | View recent audit execution logs for a specific database |
| `sw-connector db remove <alias>` | Detach and remove a database from the local configuration |

### Daemon & Lifecycle Management

| Command | Description |
| :--- | :--- |
| `sw-connector start` | Start the connector in foreground mode |
| `sw-connector start --daemon` | Start the connector as a background daemon process |
| `sw-connector stop` | Send `SIGTERM` to the daemon and clean up PID files (`--force` for `SIGKILL`) |
| `sw-connector status` | Show real-time process health, connection channel states, and active database count |
| `sw-connector clean` | Stop running daemons and remove stale PID files, status files, and orphaned sockets |
| `sw-connector doctor` | Run pre-flight checks: configs, file permissions, node version, and database reachability |

### Configuration Management (`config`)

| Command | Description |
| :--- | :--- |
| `sw-connector config show` | View sanitized machine configuration (`--token` reveals the pairing token) |
| `sw-connector config get <key>` | Read a specific configuration key (e.g. `cloud_url`, `permission`, `log_level`) |
| `sw-connector config set <key> <val>` | Update a specific configuration key |
| `sw-connector config path` | Print the filesystem paths to all configuration, audit, and log files |

### Security & Audit (`logs`, `audit`)

| Command | Description |
| :--- | :--- |
| `sw-connector logs` | View the cryptographic audit log (`--limit <n>`, `--user <id>`, `--action <query\|migrate>`) |
| `sw-connector logs --follow` | Stream live audit log events as they execute |
| `sw-connector audit verify` | Verify the cryptographic SHA-256 hash chain to ensure logs have not been tampered with |

---

## Supported Engines & Limitations

| Capability | PostgreSQL | MySQL | MongoDB |
| :--- | :--- | :--- | :--- |
| Read queries | ✅ `SELECT`/`SHOW` | ✅ `SELECT`/`DESCRIBE`/`EXPLAIN` | ✅ `find`/`aggregate`/`count`/`distinct` |
| Write queries | ✅ subject to permission | ✅ subject to permission | ❌ refused by the connector |
| Schema introspection | ✅ | ❌ | ❌ |
| Migration engine | ✅ | ❌ | ❌ |
| Query cancellation | ✅ | ❌ | ❌ |
| `db test --detailed` | ✅ full diagnostics | ⚠️ connectivity only | ⚠️ connectivity only |

- Introspection, migrations, and cancellation are PostgreSQL-only. Against a MySQL or MongoDB entry the daemon returns `unsupported_database_operation`; those operations never fall through to PostgreSQL code. `db test --detailed` on MySQL or MongoDB still verifies the connection and reports a note that the extra PostgreSQL catalog diagnostics do not apply.
- MySQL `SHOW`, `SET`, `CALL`, `PREPARE`, and `LOAD DATA` never satisfy a read intent: they classify as non-reads where the grammar accepts them and fail closed otherwise, so cloud requests for them are refused. Use the engine's own tooling for server administration.
- MySQL `EXPLAIN ANALYZE` does not parse under the MySQL grammar and is refused; `EXPLAIN SELECT` is a read.
- Before every MySQL statement the connector removes `NO_BACKSLASH_ESCAPES`, `ANSI_QUOTES`, and `ANSI` from the session `sql_mode`, so the server and `node-sql-parser` agree on where a string ends. Use backticks for identifiers; escaped quotes are lexed the standard MySQL way.
- MongoDB is read-only through the connector regardless of the local permission level: no write method and no write pipeline stage is reachable. `distinct` cannot be bounded server-side, so its result is capped after retrieval; `find` and `aggregate` are capped during execution.
- No other engines are supported. Microsoft SQL Server, Cassandra, Redis, DynamoDB, Neo4j, and warehouses are not connector targets.
- PostgreSQL behavior is unchanged, and the `pg-connector` binary remains available as an alias.

### Read-only database roles

The connector's transaction posture is a backstop, not a substitute for database authorization. Use a dedicated role whose grants are read-only:

PostgreSQL:

```sql
CREATE ROLE sw_reader LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE acme_prod TO sw_reader;
GRANT USAGE ON SCHEMA public TO sw_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO sw_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO sw_reader;
```

MySQL:

```sql
CREATE USER 'sw_reader'@'%' IDENTIFIED BY '...';
GRANT SELECT ON orders_prod.* TO 'sw_reader'@'%';
-- No INSERT/UPDATE/DELETE, no CREATE/DROP/ALTER, no EXECUTE.
```

MongoDB:

```js
db.getSiblingDB('events').createUser({
  user: 'sw_reader',
  pwd: '...',
  roles: [{ role: 'read', db: 'events' }],
});
```

For MongoDB, point `--auth-source` at the database that holds the user (often `admin`), and grant `read` only on the target database. The built-in `read` role denies `insert`/`update`/`delete` and the collection writes that `$out` and `$merge` require.

---

## Production Deployment & 24/7 Autostart

### 1. Running as a Linux Systemd Service (EC2 / Ubuntu / Debian)

For production deployments on dedicated hosts or cloud VMs, use systemd to manage automatic restarts:

1. Install the connector globally, as the user that will run the service. Use a
   versioned, per-user prefix rather than a global root install: `sudo npm
   install -g` runs third-party install scripts as root and writes root-owned
   files into a directory every account on the host can reach.
   ```bash
   npm install -g --prefix "$HOME/.local" @schema-weaver/pg-connector
   export PATH="$HOME/.local/bin:$PATH"
   ```
2. Initialize and configure your database as your service user:
   ```bash
   sw-connector init
   sw-connector db add --url postgresql://app_user@127.0.0.1:5432/app_db --alias app-db --project main --password-stdin
   ```
3. Generate and install the systemd unit file:
   ```bash
   node $(npm root -g)/@schema-weaver/pg-connector/scripts/generate-systemd-service.mjs \
     --user ubuntu --output ./schemaweaver.service
   sudo cp schemaweaver.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now schemaweaver
   ```
4. Verify status:
   ```bash
   sudo systemctl status schemaweaver
   sw-connector status
   ```

### 2. Universal Autostart with PM2 (Cross-OS)

To ensure the connector runs 24/7, survives terminal closure, and restarts on system reboot across **Linux, macOS, and Windows**:

```bash
# Install PM2 if not already installed
npm install -g pm2

# Start sw-connector with auto-restart supervisor
pm2 start sw-connector --name schemaweaver -- start

# Save process list and enable system boot startup
pm2 save
pm2 startup
```

### 3. Running in Docker / Containerized Environments

```dockerfile
FROM node:20-alpine
WORKDIR /app
RUN npm install -g @schema-weaver/pg-connector
USER node
ENV HOME=/home/node
CMD ["sw-connector", "start"]
```

Mount your local configuration directory into `/home/node/.sw-agent`:
```bash
docker run -d \
  --name schemaweaver-connector \
  -v ~/.sw-agent:/home/node/.sw-agent \
  -e SW_AGENT_DB_PASSWORD="my-secure-password" \
  schemaweaver-connector
```

---

## Private VPC, Zero-Ingress & Corporate Forward-Proxy Environments

The connector is engineered specifically for secure enterprise networks and private VPCs:

- **Zero Ingress Rules (0 Inbound Open Ports)**: The daemon **never** executes `server.listen()`. It opens no ports on the host. Firewalls and AWS Security Groups need **zero inbound rules** (`0.0.0.0:ANY` blocked).
- **Outbound-Only Over TLS**: Initiates outbound WSS connections on the standard HTTPS port, traversing NAT Gateways without custom port rules. Plaintext `ws://` cloud URLs are refused at startup.
- **Corporate TLS Inspection**: For forward proxies that intercept TLS, point Node at your organisation's CA with `NODE_EXTRA_CA_CERTS`.
- **Air-Gapped / 100% Offline Direct Mode**: For strictly isolated networks with no internet egress, the CLI executes queries, tests, and audit verification directly over the local database protocol — PostgreSQL, MySQL, or MongoDB — without external network calls (`sw-connector db query <alias> "<sql-or-json>"`).

---

## Programmatic API (Client & Runtime SDK)

`@schema-weaver/pg-connector` provides full programmatic exports for custom integrations and automated workflows.

### Client Example: Executing Queries Locally

The package exports the same building blocks the daemon uses, so you can embed
query execution in your own tooling.

```typescript
import { PoolManager, QueryRunner } from '@schema-weaver/pg-connector';

const pools = new PoolManager();
const runner = new QueryRunner({ poolManager: pools });

// 1. One-shot parameterized query (bound parameters; never string-interpolated)
const result = await runner.runOneShot(
  { sql: 'SELECT id, email, created_at FROM users WHERE status = $1 LIMIT 50',
    params: ['active'],
    intent: 'read' },
  { dbEntry, request_id: crypto.randomUUID(), classification },
);

console.log(`Executed in ${result.ms}ms:`, result.rows);

// 2. Streaming query, delivered chunk by chunk
await runner.runStreaming(
  { sql: 'SELECT * FROM event_logs ORDER BY id ASC', intent: 'read' },
  { dbEntry, request_id, classification,
    onChunk: async (chunk) => console.log(`Chunk ${chunk.chunk_index}: ${chunk.rows.length} rows`) },
);
```

To drive the relay itself, use `AgentSession` (wake + data channels), wiring
`onMessage` to a `Dispatcher` with your own permission checker and a
`DriverRegistry` built from the PostgreSQL, MySQL, and MongoDB drivers.

The common driver contract — `DatabaseDriver` in `src/drivers/types.ts` — is
what the daemon and the local CLI both call. It exposes `classify`,
`testConnection`, `runOneShot`, `runStreaming`, `redactConfig`, and the
capability flags the dispatcher uses to refuse introspection, migrations, or
cancellation on engines that do not implement them.

---

## Security Architecture & Controls

Schema Weaver’s connector architecture applies defense-in-depth security controls:

| Security Domain | Implementation | Verification |
| :--- | :--- | :--- |
| **Credential Boundary (LCB)** | Passwords and connection strings remain on customer host. Resolved locally and passed straight to a driver; never serialised into any message. MongoDB credentials are stored field-by-field so the password is encrypted like every other engine. | `src/execution/pool.ts` (`acquire()`) & `src/drivers/credentials.ts` · Local surface tests |
| **Read-Only Enforcement (CERO)** | PostgreSQL statements are parsed with `libpg_query` and a `SELECT` is a read only when every function is proved `IMMUTABLE` and not `SECURITY DEFINER` by `pg_proc`. MySQL is parsed with `node-sql-parser` and only `SELECT`/`DESCRIBE`/`EXPLAIN` can be reads, with no stored functions. MongoDB accepts only `find`/`aggregate`/`count`/`distinct` and rejects write stages recursively. Multi-statement input is refused; `read_only` adds `default_transaction_read_only = on` (PostgreSQL), `SET SESSION TRANSACTION READ ONLY` plus `START TRANSACTION READ ONLY` (MySQL), and forced read concern/preference (MongoDB). | `src/execution/statement-classifier.ts`, `src/drivers/mysql.ts`, `src/drivers/mongodb.ts` & `src/permissions/role-policy.ts` · Classifier, driver and permission tests |
| **Message Authentication** | Each data-channel envelope carries an HMAC over its canonical form, a per-message nonce, and a timestamp, all bound to a key derived from the session token. | `src/protocol/envelope.ts` · Envelope auth tests |
| **Telemetry Privacy** | SQL previews and fingerprints are produced by a dialect-aware redactor: PostgreSQL literals and dollar quotes, MySQL backslash escapes and backtick identifiers, and MongoDB JSON values are replaced before anything is transmitted or logged. A construct the lexer cannot fully account for becomes `/* unredactable */`. | `src/audit/redact.ts` · Redaction tests |
| **Data Retention** | Query results are processed ephemerally in RAM and forwarded to the browser. The connector never writes row data to disk. | `src/execution/query-runner.ts` & `src/drivers/*.ts` · In-memory stream tests |
| **Tamper-Evident Audit Trail** | Records are chained with HMAC-SHA256 under a locally-held key, carry a monotonic sequence number, and are anchored in a separate head file. Verified on demand. | `src/audit/chain.ts` & `src/audit/local-writer.ts` · `sw-connector audit verify` |

> [!NOTE]
> To report a security vulnerability or view disclosure guidelines, see [SECURITY.md](./SECURITY.md).

### Local File Permissions

All files created by `@schema-weaver/pg-connector` reside in `~/.sw-agent/`, which is created with POSIX `0o700`, and are written `0o600` (read/write by the owner only):

- `sw-agent.config.json` — Machine label, Agent ID, Cloud URL, permission level.
- `databases.config.json` — Local database configurations, user names, and encrypted passwords.
- `audit/audit.jsonl` — Cryptographically chained audit event records. The directory itself is `0o700`.
- `audit.key` — Local key used to chain and verify those records.
- `sw-agent.pid` / `sw-agent.status` — Ephemeral runtime state files.

One file lives outside the agent home by design: `~/.sw-agent-credential.key`, mode `0o400`, holds the key the stored database passwords are encrypted under. Copy it with the agent home or those passwords will not decrypt.

---

## Development & Testing

```bash
# Clone and enter directory
cd sw-agent

# Install dependencies
npm install

# Type-check TypeScript codebase
npm run typecheck

# Lint source code
npm run lint

# Run unit tests
npm test

# Run protocol and execution suites
npm run test:protocol
npm run test:execution
npm run test:permissions

# Driver tests. The integration cases skip unless a server is configured;
# a configured server that is unreachable fails instead of skipping.
SW_AGENT_TEST_MYSQL_PW=... SW_AGENT_TEST_MYSQL_HOST=127.0.0.1 \
  SW_AGENT_TEST_MYSQL_USER=root SW_AGENT_TEST_MYSQL_DATABASE=mysql \
  node --test --import tsx "src/tests/drivers/**/*.test.ts"

SW_AGENT_TEST_MONGO_PW=... SW_AGENT_TEST_MONGO_HOST=127.0.0.1 \
  SW_AGENT_TEST_MONGO_USER=root SW_AGENT_TEST_MONGO_DATABASE=sw_agent_test \
  node --test --import tsx "src/tests/drivers/**/*.test.ts"

# Build distribution bundles (CJS, ESM, Types)
npm run build
```

The MySQL integration test creates a uniquely named table, proves a forged
"read" cannot insert into it inside `START TRANSACTION READ ONLY`, then proves
the same insert succeeds when the session is not read-only. The MongoDB test
proves the four read methods execute and that write methods and `$out` are
refused before a client call.

---

## License

MIT © 2026 [Schema Weaver](https://schemaweaver.dev)
