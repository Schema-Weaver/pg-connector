# @schema-weaver/pg-connector

> **Secure PostgreSQL Connector for Schema Weaver with Local Credential Boundary (LCB) and Connector-Enforced Read-Only Execution (CERO).**  
> Connects local or VPC-hosted databases to Schema Weaver. Database credentials never leave your environment.

[![npm version](https://img.shields.io/npm/v/@schema-weaver/pg-connector.svg)](https://www.npmjs.com/package/@schema-weaver/pg-connector)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node: >=18](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org)
[![TypeScript: 5+](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org)
[![Security: LCB + CERO](https://img.shields.io/badge/Security-LCB%20%2B%20CERO-purple.svg)](#security-architecture)

---

## What is `@schema-weaver/pg-connector`?

`@schema-weaver/pg-connector` (executable as `pg-connector`, `sw-agent`, or `schemaweaver`) is a lightweight on-premises daemon and client library that links customer PostgreSQL databases with the [Schema Weaver](https://schemaweaver.dev) web platform (Data Explorer, SQL Editor, and Schema Migration Engine).

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
               (PostgreSQL 12 and later)
```

### 1. Local Credential Boundary (LCB)
Database host, port, username, password, connection strings, and SSL private keys **remain strictly inside your environment** in `~/.sw-agent/databases.config.json` (POSIX file mode `0o600`) or local OS environment variables. Passwords stored in that file are encrypted at rest with AES-256-GCM under a scrypt-derived key. The cloud control plane receives scoped identities (`agent_id`, `db_alias`, and `database` name) plus the query text, results, and schema needed to serve your session, carried over TLS, and an active connection token hash: the agent sends `HMAC-SHA256(token, "sw-agent/relay-auth/v1")` rather than the token itself, so the long-lived secret never appears on the wire.

### 2. Connector-Enforced Read-Only Execution (CERO)
The connector acts as the final gatekeeper between external requests and your database engine:
- **Real PostgreSQL Parser**: Every statement received from the cloud is parsed with PostgreSQL's own grammar (`libpg_query`) and classified from the resulting parse tree — not from a keyword guess. Multi-statement input is refused outright, and `SELECT … INTO`, `FOR UPDATE`, writable CTEs, and calls to privileged functions (`pg_read_file`, `lo_import`, `dblink_exec`, `setval`, …) are detected structurally. Classification is allowlist-based: only `SELECT` and `SHOW` are reads, and anything that fails to parse is denied.
- **PostgreSQL Verdict Before "Read"**: A `SELECT` counts as a read only when every function it references is reported by `pg_proc` as `IMMUTABLE` and not `SECURITY DEFINER`. Anything else — volatile, stable, security-definer, or unresolvable — is escalated to the DDL capability requirement, so an operator-written function cannot be reached through a read. This is deliberately stricter than PostgreSQL's own guarantee: a `SELECT now()` needs the `ddl` capability.
- **Anti-Spoofing**: The browser's claimed `intent` is advisory only. If it disagrees with the parsed classification, the request is rejected — and no `intent` value grants an exemption.
- **Enforced by the database too**: For a `read_only` database the connection itself runs with `default_transaction_read_only = on`, so PostgreSQL raises `25006` on a write even if classification were wrong. This constrains writes in the connector's own transaction; the connected database role remains the final authority, and `pg-connector doctor` reports its attributes.
- **Role-Based Access Control**: Enforces 4 permission levels (`read_only`, `auto_upgrade`, `manual`, `full`) and role capabilities (`admin`, `developer`, `data_reader`, `viewer`) locally before touching the connection pool. The role arrives inside an envelope authenticated by the relay, and must fall within both the set negotiated for the session and this installation's `security.max_negotiable_role` ceiling (default `developer`).

### 3. Transient Data Plane
Query results are streamed in memory over TLS WebSocket connections directly to the browser session. Rows exist ephemerally in RAM buffers during transit; the connector **never writes them to disk**, and nothing in this package persists them to any cache or database.

### 4. Cryptographic Audit Log
Every operation (query, migration, schema introspection, cancellation) is recorded locally in `~/.sw-agent/audit/audit.jsonl` using a tamper-evident **HMAC-SHA256 cryptographic hash chain** with a monotonic sequence number and an anchored head. Each record names the database the request actually resolved to. Chain integrity is verifiable on demand with `pg-connector audit verify`.

---

## Installation

### Global CLI

```bash
# Install globally via npm
npm install -g @schema-weaver/pg-connector

# Or run directly without installation (Zero-Install):
npx @schema-weaver/pg-connector init
```

> **Available CLI binaries**: After global installation, `pg-connector`, `sw-agent`, `schemaweaver`, and `db-connector` can all be used interchangeably.

### As a Project Dependency

```bash
npm install @schema-weaver/pg-connector
```

---

## Quick Start (CLI Workflow)

### Step 1: Initialize the Connector

Initialize machine configuration and generate your connector token:

```bash
pg-connector init
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

### Step 2: Attach a PostgreSQL Database

#### Option A: Interactive Mode (with Live Connection Probe)
```bash
pg-connector db add
```
Follow the interactive prompts. The password is read from a masked prompt, stored encrypted in the local configuration file. You can instead point at an environment variable (see Option C).

#### Option B: Non-Interactive via Connection URL
```bash
# The URL carries no password: a --url with a password is refused.
pg-connector db add \
  --url postgresql://app_user@localhost:5432/acme_prod \
  --alias acme-db \
  --project acme \
  --ssl verify-full \
  --password-stdin
```

#### Option C: Non-Interactive via Command-Line Flags
```bash
pg-connector db add \
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

#### Password sources

`db add` refuses `--password` and `--pw`, and refuses a `--url` that carries a password: `process.argv` is readable by every local user. Supported channels, safest first:

| Channel | Notes |
| :--- | :--- |
| `SW_AGENT_DB_PASSWORD=<value> pg-connector db add …` | Read from the environment at run time |
| `--password-stdin` | Read from stdin |
| `--password-file <path>` | Must be mode `0600` and must not be a symlink |
| `--env <VAR>` | Stores only the variable **name**; the value is read at connect time |
| *(no flag)* | Masked interactive prompt |

> [!NOTE]
> `--ssl` accepts `disable`, `require`, `verify-ca` and `verify-full`. New entries default to `require`, which is TLS without certificate verification — set it explicitly in any environment where the database hop is not fully trusted.

### Step 3: Test & Inspect Connections

```bash
# Fast reachability ping
pg-connector db ping acme-db

# Full connection test with latency measurement
pg-connector db test acme-db

# Multi-step deep diagnostics (network, catalog, permissions, timeouts)
pg-connector db test acme-db --detailed

# Detailed configuration and connection inspection
pg-connector db show acme-db

# Execute a quick query directly from the terminal
pg-connector db query acme-db "SELECT current_database(), version();"

# Launch an interactive database console session
pg-connector db connect acme-db
```

### Step 4: Start the Background Daemon

```bash
# Foreground execution (great for testing or Docker containers)
pg-connector start

# Background daemon mode (standard server operation)
pg-connector start --daemon
```

### Step 5: Check Status & Health

```bash
pg-connector status
```
```text
  Schema Weaver Agent — Status
  ──────────────────────────────────────────────────
  Process:           running (PID 4821)
  Uptime:            4h 12m 35s
  Version:           2.0.0
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

---

## Complete CLI Command Reference

### Database Management (`db`)

| Command | Description |
| :--- | :--- |
| `pg-connector db add` | Add a database (interactive, `--url <postgres://…>` with no password, or non-interactive flags). Passwords come from the masked prompt, `--password-stdin`, `--password-file`, `--env <VAR>` or `SW_AGENT_DB_PASSWORD`; `--password`/`--pw` are refused |
| `pg-connector db list` (or `db ls`) | Display all configured databases in a formatted table |
| `pg-connector db show <alias>` | Show detailed configuration and credentials mode for a database (`--json` supported) |
| `pg-connector db edit <alias>` | Modify database settings (interactive or via flags: `--host`, `--port`, `--env`, etc.) |
| `pg-connector db test <alias>` | Test connection latency (`--detailed` for deep diagnostics) |
| `pg-connector db ping <alias>` | Quick millisecond round-trip reachability ping |
| `pg-connector db query <alias> "<SQL>"` | Execute a query and output tabular results directly in the terminal |
| `pg-connector db connect <alias>` | Open an interactive SQL REPL session directly connected to the database |
| `pg-connector db logs <alias>` | View recent audit execution logs for a specific database |
| `pg-connector db remove <alias>` | Detach and remove a database from the local configuration |

### Daemon & Lifecycle Management

| Command | Description |
| :--- | :--- |
| `pg-connector start` | Start the connector in foreground mode |
| `pg-connector start --daemon` | Start the connector as a background daemon process |
| `pg-connector stop` | Send `SIGTERM` to the daemon and clean up PID files (`--force` for `SIGKILL`) |
| `pg-connector status` | Show real-time process health, connection channel states, and active database count |
| `pg-connector clean` | Stop running daemons and remove stale PID files, status files, and orphaned sockets |
| `pg-connector doctor` | Run pre-flight checks: configs, file permissions, node version, and database reachability |

### Configuration Management (`config`)

| Command | Description |
| :--- | :--- |
| `pg-connector config show` | View sanitized machine configuration (`--token` reveals the pairing token) |
| `pg-connector config get <key>` | Read a specific configuration key (e.g. `cloud_url`, `permission`, `log_level`) |
| `pg-connector config set <key> <val>` | Update a specific configuration key |
| `pg-connector config path` | Print the filesystem paths to all configuration, audit, and log files |

### Security & Audit (`logs`, `audit`)

| Command | Description |
| :--- | :--- |
| `pg-connector logs` | View the cryptographic audit log (`--limit <n>`, `--user <id>`, `--action <query\|migrate>`) |
| `pg-connector logs --follow` | Stream live audit log events as they execute |
| `pg-connector audit verify` | Verify the cryptographic SHA-256 hash chain to ensure logs have not been tampered with |

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
   pg-connector init
   pg-connector db add --url postgresql://app_user@127.0.0.1:5432/app_db --alias app-db --project main --password-stdin
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
   pg-connector status
   ```

### 2. Universal Autostart with PM2 (Cross-OS)

To ensure the connector runs 24/7, survives terminal closure, and restarts on system reboot across **Linux, macOS, and Windows**:

```bash
# Install PM2 if not already installed
npm install -g pm2

# Start pg-connector with auto-restart supervisor
pm2 start pg-connector --name schemaweaver -- start

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
CMD ["pg-connector", "start"]
```

Mount your local configuration directory into `/home/node/.sw-agent`:
```bash
docker run -d \
  --name schemaweaver-connector \
  -v ~/.sw-agent:/home/node/.sw-agent \
  -e DB_PASSWORD="my-secure-password" \
  schemaweaver-connector
```

---

## Private VPC, Zero-Ingress & Corporate Forward-Proxy Environments

The connector is engineered specifically for secure enterprise networks and private VPCs:

- **Zero Ingress Rules (0 Inbound Open Ports)**: The daemon **never** executes `server.listen()`. It opens no ports on the host. Firewalls and AWS Security Groups need **zero inbound rules** (`0.0.0.0:ANY` blocked).
- **Outbound-Only Over TLS**: Initiates outbound WSS connections on the standard HTTPS port, traversing NAT Gateways without custom port rules. Plaintext `ws://` cloud URLs are refused at startup.
- **Corporate TLS Inspection**: For forward proxies that intercept TLS, point Node at your organisation's CA with `NODE_EXTRA_CA_CERTS`.
- **Air-Gapped / 100% Offline Direct Mode**: For strictly isolated networks with no internet egress, the CLI executes queries, tests, and audit verification directly over the local PostgreSQL wire protocol without external network calls (`pg-connector db query <alias> "<sql>"`).

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
`onMessage` to a `Dispatcher` with your own permission checker.

---

## Security Architecture & Controls

Schema Weaver’s connector architecture applies defense-in-depth security controls:

| Security Domain | Implementation | Verification |
| :--- | :--- | :--- |
| **Credential Boundary (LCB)** | Passwords and connection strings remain on customer host. Resolved locally and passed straight to the pool; never serialised into any message. | `src/execution/pool.ts` (`acquire()`) · Local surface tests |
| **Read-Only Enforcement (CERO)** | Every statement is parsed with the real PostgreSQL grammar (`libpg_query`) and classified from the parse tree, and a `SELECT` is a read only when every function it calls is proved `IMMUTABLE` and not `SECURITY DEFINER` by `pg_proc`. Multi-statement input is refused; `read_only` additionally runs the connection with `default_transaction_read_only = on`. | `src/execution/statement-classifier.ts`, `src/execution/function-effects.ts` & `src/permissions/role-policy.ts` · Classifier and permission tests |
| **Message Authentication** | Each data-channel envelope carries an HMAC over its canonical form, a per-message nonce, and a timestamp, all bound to a key derived from the session token. | `src/protocol/envelope.ts` · Envelope auth tests |
| **Telemetry Privacy** | SQL previews are passed through a PostgreSQL-aware lexer that replaces literals, comments, and dollar-quoted bodies before anything is transmitted or logged. | `src/audit/redact.ts` · Redaction tests |
| **Data Retention** | Query results are processed ephemerally in RAM and forwarded to the browser. The connector never writes row data to disk. | `src/execution/query-runner.ts` · In-memory stream tests |
| **Tamper-Evident Audit Trail** | Records are chained with HMAC-SHA256 under a locally-held key, carry a monotonic sequence number, and are anchored in a separate head file. Verified on demand. | `src/audit/chain.ts` & `src/audit/local-writer.ts` · `pg-connector audit verify` |

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

# Build distribution bundles (CJS, ESM, Types)
npm run build
```

---

## License

MIT © 2026 [Schema Weaver](https://schemaweaver.dev)
