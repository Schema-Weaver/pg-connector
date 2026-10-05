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
               (PostgreSQL 12, 13, 14, 15, 16, 17)
```

### 1. Local Credential Boundary (LCB)
Database host, port, username, password, connection strings, and SSL private keys **remain strictly inside your environment** in `~/.sw-agent/databases.config.json` (POSIX file mode `0o600`) or local OS environment variables. The cloud control plane receives only scoped identities (`agent_id`, `db_alias`, and `database` name) and an active connection token hash.

### 2. Connector-Enforced Read-Only Execution (CERO)
The connector acts as the final gatekeeper between external requests and your database engine:
- **Anti-Spoofing & Re-Classification**: Every query received from the cloud is re-parsed and re-classified locally. If a request claims `intent: 'read'` but contains write or mutating commands, it is blocked immediately.
- **Role-Based Access Control**: Enforces 4 permission levels (`read_only`, `auto_upgrade`, `manual`, `full`) and role capabilities (`admin`, `developer`, `data_reader`, `viewer`) locally before touching the database connection pool.

### 3. Transient Data Plane (Zero Cloud Data Replication)
Query results are streamed in memory over TLS WebSocket connections directly to the browser session. Rows exist ephemerally in RAM buffers during transit and are **never persisted** to any cloud database, cache, or disk storage.

### 4. Cryptographic Audit Log
Every operation (query, migration, schema introspection, cancellation) is recorded locally in `~/.sw-agent/audit/audit.jsonl` using a tamper-evident **SHA-256 cryptographic hash chain**, providing non-repudiation and auditability for SOC 2 compliance.

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
sw-agent init
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
sw-agent db add
```
Follow the interactive prompts. Passwords can be stored securely in the local configuration file or referenced dynamically from an environment variable (e.g. `$DB_PASSWORD`).

#### Option B: Non-Interactive via Connection URL
```bash
sw-agent db add \
  --url postgresql://app_user:secret_pass@localhost:5432/acme_prod \
  --alias acme-db \
  --project acme \
  --ssl require
```

#### Option C: Non-Interactive via Command-Line Flags
```bash
sw-agent db add \
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

### Step 3: Test & Inspect Connections

```bash
# Fast reachability ping
sw-agent db ping acme-db

# Full connection test with latency measurement
sw-agent db test acme-db

# Multi-step deep diagnostics (network, catalog, permissions, timeouts)
sw-agent db test acme-db --detailed

# Detailed configuration and connection inspection
sw-agent db show acme-db

# Execute a quick query directly from the terminal
sw-agent db query acme-db "SELECT current_database(), version();"

# Launch an interactive database console session
sw-agent db connect acme-db
```

### Step 4: Start the Background Daemon

```bash
# Foreground execution (great for testing or Docker containers)
sw-agent start

# Background daemon mode (standard server operation)
sw-agent start --daemon
```

### Step 5: Check Status & Health

```bash
sw-agent status
```
```text
  Schema Weaver Agent — Status
  ──────────────────────────────────────────────────
  Process:           running (PID 4821)
  Uptime:            4h 12m 35s
  Version:           0.1.0
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
| `sw-agent db add` | Add a database (interactive, `--url <postgres://...>`, or non-interactive flags) |
| `sw-agent db list` (or `db ls`) | Display all configured databases in a formatted table |
| `sw-agent db show <alias>` | Show detailed configuration and credentials mode for a database (`--json` supported) |
| `sw-agent db edit <alias>` | Modify database settings (interactive or via flags: `--host`, `--port`, `--env`, etc.) |
| `sw-agent db test <alias>` | Test connection latency (`--detailed` for deep diagnostics) |
| `sw-agent db ping <alias>` | Quick millisecond round-trip reachability ping |
| `sw-agent db query <alias> "<SQL>"` | Execute a query and output tabular results directly in the terminal |
| `sw-agent db connect <alias>` | Open an interactive SQL REPL session directly connected to the database |
| `sw-agent db logs <alias>` | View recent audit execution logs for a specific database |
| `sw-agent db remove <alias>` | Detach and remove a database from the local configuration |

### Daemon & Lifecycle Management

| Command | Description |
| :--- | :--- |
| `sw-agent start` | Start the connector in foreground mode |
| `sw-agent start --daemon` | Start the connector as a background daemon process |
| `sw-agent stop` | Send `SIGTERM` to the daemon and clean up PID files (`--force` for `SIGKILL`) |
| `sw-agent status` | Show real-time process health, connection channel states, and active database count |
| `sw-agent clean` | Stop running daemons and remove stale PID files, status files, and orphaned sockets |
| `sw-agent doctor` | Run pre-flight checks: configs, file permissions, node version, and database reachability |

### Configuration Management (`config`)

| Command | Description |
| :--- | :--- |
| `sw-agent config show` | View sanitized machine configuration (`--token` reveals the pairing token) |
| `sw-agent config get <key>` | Read a specific configuration key (e.g. `cloud_url`, `permission`, `log_level`) |
| `sw-agent config set <key> <val>` | Update a specific configuration key |
| `sw-agent config path` | Print the filesystem paths to all configuration, audit, and log files |

### Security & Audit (`logs`, `audit`)

| Command | Description |
| :--- | :--- |
| `sw-agent logs` | View the cryptographic audit log (`--limit <n>`, `--user <id>`, `--action <query\|migrate>`) |
| `sw-agent logs --follow` | Stream live audit log events as they execute |
| `sw-agent audit verify` | Verify the cryptographic SHA-256 hash chain to ensure logs have not been tampered with |

---

## Production Deployment & 24/7 Autostart

### 1. Running as a Linux Systemd Service (EC2 / Ubuntu / Debian)

For production deployments on dedicated hosts or cloud VMs, use systemd to manage automatic restarts:

1. Install the connector globally:
   ```bash
   sudo npm install -g @schema-weaver/pg-connector
   ```
2. Initialize and configure your database as your service user:
   ```bash
   pg-connector init
   pg-connector db add --url postgresql://app_user:pass@127.0.0.1:5432/app_db --alias app-db --project main
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

## Private VPC, Zero-Ingress & Proxy Environments

The connector is engineered specifically for secure enterprise networks and private VPCs:

- **Zero Ingress Rules (0 Inbound Open Ports)**: The daemon **never** executes `server.listen()`. It opens no ports on the host. Firewalls and AWS Security Groups need **zero inbound rules** (`0.0.0.0:ANY` blocked).
- **Outbound-Only Over Standard Port 443**: Initiates outbound WSS connections over port 443 (standard HTTPS), traversing NAT Gateways without custom port rules.
- **Corporate Forward Proxy Support**: Respects `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables for corporate firewalls (Zscaler, Squid, Envoy).
- **Air-Gapped / 100% Offline Direct Mode**: For strictly isolated networks with no internet egress, the CLI executes queries, tests, and audit verification directly over the local PostgreSQL wire protocol without external network calls (`pg-connector db query <alias> "<sql>"`).

---

## Programmatic API (Client & Runtime SDK)

`@schema-weaver/pg-connector` provides full programmatic exports for custom integrations and automated workflows.

### Client Example: Executing Queries via Relay

```typescript
import { AgentClient } from '@schema-weaver/pg-connector';

const client = new AgentClient({
  relayUrl: 'wss://api.schemaweaver.dev',
  agentId: 'agt_prod-bastion_8f2b1a9c',
  token: process.env.SW_AGENT_TOKEN,
});

await client.connect();

const ctx = {
  project: 'acme',
  role: 'developer' as const,
  userId: 'usr_sarah_123',
};

// 1. One-shot parameterized query
const result = await client.query({
  sql: 'SELECT id, email, created_at FROM users WHERE status = $1 LIMIT 50',
  params: ['active'],
  intent: 'read',
}, ctx);

console.log(`Executed in ${result.ms}ms:`, result.rows);

// 2. High-volume streaming query (chunked async iterable)
for await (const chunk of client.streamQuery({
  sql: 'SELECT * FROM event_logs ORDER BY id ASC',
  intent: 'read',
}, ctx)) {
  console.log(`Chunk ${chunk.chunkIndex}: ${chunk.rows.length} rows`);
}

// 3. Schema Introspection
const schema = await client.introspect(ctx);
console.log('Detected schemas and tables:', schema.tables);

await client.disconnect();
```

---

## Security Architecture & SOC 2 Compliance

Schema Weaver’s connector architecture was audited and certified against real production workflows:

| Security Domain | Implementation | Code Verification |
| :--- | :--- | :--- |
| **Credential Boundary (LCB)** | Passwords and connection strings remain on customer host. Stripped before transmission. | [`sw-agent/src/cli/daemon/runtime.ts:175-179`](file:///c:/schema-weaver/sw-agent/src/cli/daemon/runtime.ts#L175-L179) |
| **Read-Only Enforcement (CERO)** | Connector re-parses incoming SQL independently. Reject-by-default intent matching. | [`sw-agent/src/permissions/checker.ts:38-47`](file:///c:/schema-weaver/sw-agent/src/permissions/checker.ts#L38-L47) |
| **Telemetry Privacy (GDPR/SOC 2)** | SQL statements in cloud telemetry have string and numeric literals redacted to `'?'`. | [`backend/.../event-logger.service.js:31-36`](file:///c:/schema-weaver/backend/services/database-connection/agent-relay/event-logger.service.js#L31-L36) |
| **Data Retention** | Query results are processed ephemerally in RAM and forwarded to the browser. Zero cloud disk persistence. | [`backend/.../query.routes.js:55`](file:///c:/schema-weaver/backend/routes/database-connection/agent-relay/query.routes.js#L55) |
| **Tamper-Evident Audit Trail** | Cryptographic hash chaining (`hash = sha256(prev_hash + event_data)`). Verified on demand. | [`sw-agent/src/audit/chain.ts`](file:///c:/schema-weaver/sw-agent/src/audit/chain.ts) |

### Local File Permissions

All files created by `@schema-weaver/pg-connector` reside in `~/.sw-agent/` with POSIX `0o600` permissions (read/write by the owner only):

- `sw-agent.config.json` — Machine label, Agent ID, Cloud URL, permission level.
- `databases.config.json` — Local database configurations, user names, and encrypted/stored passwords.
- `audit.log` — Cryptographically chained audit event records.
- `sw-agent.pid` / `sw-agent.status` — Ephemeral runtime state files.

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
