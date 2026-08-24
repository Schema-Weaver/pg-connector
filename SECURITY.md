# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `pg-connector`, please
report it responsibly:

**Email**: security@schemaweaver.vivekmind.com

Please include:
- A description of the vulnerability
- Steps to reproduce
- Impact assessment
- Any suggested fixes

We will acknowledge your report within **48 hours** and provide a detailed
response within **5 business days**. We will work with you to understand and
resolve the issue before any public disclosure.

**Do NOT open a public GitHub issue for security vulnerabilities.**

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✓ Current release  |

## Security Architecture

### Threat Model

`pg-connector` (formerly `sw-agent`) is a daemon that bridges the
Schema Weaver browser IDE to PostgreSQL databases. Its security design is based
on a **zero-trust, outbound-only, least-privilege** model:

```
┌──────────────┐            ┌────────────────┐            ┌──────────────┐
│   Browser    │◄──WSS/TLS──│  Cloud Gateway │◄──WSS/TLS──│  sw-agent    │
│   (IDE)      │            │  (relay only)  │            │  (your VPC)  │
└──────────────┘            └────────────────┘            └──────┬───────┘
                                                                 │ pg (local)
                                                          ┌──────▼───────┐
                                                          │  PostgreSQL  │
                                                          └──────────────┘
```

### Core Security Properties

#### 1. Zero Credential Transit
- Database passwords (`password_stored`, `password_env`) **never leave the
  machine** where the agent runs.
- Passwords are resolved locally (from config file or environment variable) and
  passed directly to the `pg` connection pool.
- Neither the SSE (wake) channel nor the WSS (data) channel ever transmit
  database credentials.

#### 2. Outbound-Only Connections
- The agent **never calls `listen()`** on any port.
- Both channels (SSE and WSS) are outbound HTTPS/WSS connections initiated by
  the agent.
- **No inbound firewall rules required** — works in any VPC, private subnet,
  or NAT-only environment.

#### 3. Token-Based Authentication
- Agent authentication uses a machine-scoped token (`swagt_...`) generated
  during `init`.
- Data channel tokens are short-lived, issued per-session by the cloud gateway.
- Tokens are transmitted exclusively via `Authorization: Bearer` headers —
  **never in URL query parameters** — to prevent leakage in proxy/CDN logs.

#### 4. Role-Based Access Control (RBAC)
Every incoming request carries a `role` and `permission_level`. The agent
enforces these **server-side** before executing any SQL:

| Role | Read | Write | DDL | Migrate | Cancel |
|------|------|-------|-----|---------|--------|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `developer` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `data_reader` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `viewer` | ✓ | ✗ | ✗ | ✗ | ✗ |

**Anti-spoofing**: The agent re-classifies SQL statements independently — it
does not trust the browser's claimed `intent`. If the browser says `read` but
the SQL is `INSERT`, the request is rejected with `intent_mismatch`.

#### 5. Permission Levels

| Level | Behavior |
|-------|----------|
| `read_only` | Only SELECT/read queries allowed |
| `auto_upgrade` | Reads + pre-registered migration plans auto-approved |
| `manual` | Every write/DDL requires browser-side manual approval |
| `full` | All operations auto-approved (role checks still apply) |

#### 6. Tamper-Evident Audit Log
- Every action (query, migration, cancel, introspect) is logged to a local
  JSONL file with a **SHA-256 hash chain**.
- Each event's `hash` = `SHA-256(canonical(event) + prev_hash)`.
- The first event chains from `prev_hash = "0" × 64`.
- Chain integrity is verifiable via `schemaweaver audit verify`.
- SQL previews are **redacted** (literals replaced with `?`) and **truncated**
  to 200 characters to prevent accidental secret leaks.
- Statement fingerprinting uses the redacted form so different literal values
  map to the same fingerprint.

#### 7. TLS/SSL Enforcement
PostgreSQL connections support:
- `disable` — no TLS
- `require` — TLS without certificate verification
- `verify-ca` — TLS with CA certificate verification
- `verify-full` — TLS with CA + hostname verification

Custom CA root certificates (`ssl_root_cert`) are supported for private CAs.

#### 8. Local File Security
- Agent home directory (`~/.sw-agent`) is created with `0o700` permissions.
- Config files contain database credentials and should have `0o600` permissions.
- The `init` command creates the directory with restricted permissions.

#### 9. Graceful Shutdown & Resilience
- Handles `SIGINT` and `SIGTERM` with a coordinated shutdown sequence.
- Each resource (pools, channels, audit writers) has individual cleanup with
  per-resource timeouts.
- SSE wake channel uses exponential backoff with jitter for reconnection.
- Connection pools have idle timeouts to release unused resources.

---

## SOC 2 Compliance Alignment

The following checklist maps `sw-agent` security controls to SOC 2 Trust
Service Criteria:

### CC6.1 — Logical Access Controls
- [x] Role-based capability enforcement (`ROLE_CAPABILITIES` matrix)
- [x] Permission levels gate all SQL execution
- [x] Anti-spoofing: SQL re-classification independent of browser claims
- [x] Short-lived, session-scoped data channel tokens

### CC6.6 — System Boundary Protection
- [x] Outbound-only connections — no `listen()` calls
- [x] TLS/WSS for all cloud communication
- [x] PostgreSQL TLS with configurable verification modes

### CC7.2 — Monitoring & Detection
- [x] SHA-256 hash-chained audit log for tamper evidence
- [x] Every action logged with user, role, decision, outcome, duration
- [x] SQL fingerprinting for pattern analysis without data exposure
- [x] Chain verification command (`audit verify`)

### CC6.7 — Data Confidentiality
- [x] Database credentials never transmitted — resolved locally
- [x] SQL previews redacted before logging (literals → `?`)
- [x] Preview truncation to 200 characters
- [x] Tokens in headers only, never in URLs

### CC7.4 — Incident Response
- [x] Graceful shutdown coordinator with per-resource timeouts
- [x] Exponential backoff with jitter on reconnection
- [x] Error tracking and diagnostic logging
- [x] `doctor` command for pre-flight health checks

### CC8.1 — Change Management
- [x] Migration plan pre-registration for `auto_upgrade` mode
- [x] Manual approval flow for sensitive operations
- [x] Non-transactional DDL detection prevents transaction wrapping errors
