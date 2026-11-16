# MediSentinel

**A Centralized Audit Trail Management System for Integrated Pharmacy Operations**

MediSentinel collects, preserves and verifies significant activity from independent pharmacy systems, such as the PharmaCore POS and the Pharmacy Inventory Management System. Those systems submit structured audit events through a signed REST API. MediSentinel stores them in a tamper-evident, append-only trail and makes them searchable. It also detects suspicious patterns, supports investigations, verifies data quality and produces reports.

MediSentinel **does not perform** POS, inventory or other business operations. It only audits them.

Built with Node.js, Express, the XianFire framework (`.xian` Handlebars views), Sequelize, MySQL 8, Tailwind CSS, Chart.js and Jest.

---

## Quick start

Requirements: Node.js 18 or later, and MySQL 8 running locally or reachable over the network.

```bash
npm install
npm run setup      # creates .env with random keys (never overwrites existing values)
                   # → edit DB_* in .env if MySQL is not root@localhost without a password
npm run migrate    # creates the database and tables, installs triggers and seeds reference data
npm start          # http://localhost:3000
```

Sign in with `ADMIN_INITIAL_USERNAME` / `ADMIN_INITIAL_PASSWORD` from `.env`, then change the password under **Settings → My password**.

> MediSentinel refuses to start if `AUDIT_SIGNING_KEY` or `CREDENTIAL_ENCRYPTION_KEY` is missing. **Back these keys up**: losing the signing key makes existing records unverifiable, and losing the encryption key invalidates every integration credential.

### Accounts and appearance

- **Create account**: people without an account can sign up from the sign-in page (`/register`). New accounts get the **Read-Only Viewer** role and stay inactive until an administrator approves them under **User Management** (filter *Pending approval*, then **Approve**). Administrators receive an *Account Awaiting Approval* notification. Turn sign-up off with the setting *Allow "Create account" on the sign-in page* (Settings → System → Security).
- **Dark mode**: use the moon/sun button in the top bar, the theme picker in the user menu, or **Settings → Appearance** (Light, Dark or System). The choice is saved per browser. The dark theme uses soft, low-glare colours for long sessions; printouts are always light.
- After changing any `.xian` view or `src/styles/input.css`, run `npm run build:css`.

### What you will see on first start

The database contains only reference data: roles, event types, alert rules, settings, and the two expected integrations (PharmaCore POS and the Inventory system). Both integrations appear as **Never connected** until they actually send authenticated traffic. No statistics or events are invented, so dashboards stay empty until real events arrive.

### Sample data

```bash
npm run seed:demo
```

Adds two test systems, **Demo POS** and **Demo Inventory**, with 14 days of activity, alerts, investigations, a QA run and three staff accounts (password `Demo@12345`):

| Account | Role |
|---|---|
| `rhea.auditor@medisentinel.local` | Auditor |
| `marco.investigator@medisentinel.local` | Investigator |
| `liza.viewer@medisentinel.local` | Read-Only Viewer |

Existing accounts are not changed. With `DEMO_TRAFFIC=true` in `.env`, the server keeps both demo systems live by sending signed heartbeats and events to its own API every minute. Without it, they show as *Disconnected* after 30 minutes, which is correct behaviour.

### Generating real test traffic

```bash
npm run dev-credential          # registers a TEST source "DEV_SIMULATOR" and prints its credential
# copy the printed MEDISENTINEL_* lines into your shell, then:
npm run simulate -- --scenario all --profile pos
```

The simulator sends real signed HTTP requests: normal sales, complete POS flows (`pos-flows`: customers, settings, branches, products, sales, authorized and unauthorized voids, reports, price checks), failed logins, voids, deletions, role changes, invalid payloads, duplicates, a batch, bad signatures and heartbeats. Every request goes through the full pipeline, so alerts, QA findings and notifications appear exactly as they would in production.

---

## Scripts

| Command | Purpose |
|---|---|
| `npm start` / `npm run dev` | Run the server (`dev` uses nodemon) |
| `npm run setup` | Generate `.env` with secure keys |
| `npm run migrate` | Apply pending migrations and seed reference data (safe to repeat) |
| `npm run seed:demo` | Add the sample dataset (once) |
| `npm run build:css` / `watch:css` | Rebuild Tailwind CSS (`public/css/app.css`) |
| `npm run dev-credential` | Issue a credential for a TEST source (development only) |
| `npm run simulate` | Send signed test events (`--scenario`, `--profile pos\|inventory`, `--count`). `--scenario pos-flows` sends a full pharmacy flow |
| `npm test` / `npm run test:unit` | Jest suites (integration tests use `medisentinel_test`) |
| `npm run route:list` | XianFire: list all routes |
| `npm run create:model` / `create:controller` | XianFire generators |

## Modules

| Sidebar | What it does |
|---|---|
| Dashboard | Live counts (events, today, connected systems, active users, failures, open alerts, pending investigations, latest QA result) and eight charts. The **Pharmacy operations** tab shows POS event, completed and voided transaction, configuration, customer, administrative, failed-event and pending-finding figures, with six charts filterable by system, branch, user, action and date |
| Audit Trail | Search and filter across all sources (including branch and *hide routine access*); record detail with the before/after diff, traceability (branch, reason, authorization, references), integrity verification, correlated events and delivery record; CSV export. Tabs: **Transaction timeline**, **Void investigation**, **Configuration changes** (before/after per setting) and **Cross-system** activity with verified identity mappings |
| User Activity | Per-system user list, failed logins, restricted access, role changes, repeated sensitive actions; per-user profile |
| System Integrations | Register systems, issue and revoke credentials (secret shown once), event registry, connection tests, monitoring of measured health, integration logs |
| Suspicious Activities | Rule-based alerts: acknowledge, assign, notes, resolve or dismiss, full history; configurable rules |
| Investigations | Cases linked to original audit records, assignment, status workflow, notes, findings; every change audited |
| Audit Reports | 13 reports with filters, print layout and CSV export (generation and exports are audited) |
| Quality Assurance / QA Findings | Verification runs (integrity, validation, coverage, integration quality, plus POS event validation, transaction audit consistency, configuration audit verification and cross-system consistency), history, coverage matrix, findings workflow |
| Notifications | Critical alerts, suspicious activity, integration and validation failures, integrity failures, QA findings, assignments |
| User Management | Internal accounts and role permissions (separate from external system users) |
| Settings | System settings, audit event types, key status, password change |

## Documentation

- [docs/API_INTEGRATION.md](docs/API_INTEGRATION.md) — for teams connecting a system: signing, event format, action codes, responses, retries, heartbeats
- [docs/TECHNICAL.md](docs/TECHNICAL.md) — architecture, database, integrity mechanism, detection rules, QA, security controls, roles, configuration, tests
- [clients/medisentinel-client.js](clients/medisentinel-client.js) — drop-in Node.js client with signing, retries and a durable outbox

## Project layout

```
config/        database connection (env-driven)
controllers/   request handlers
middleware/    auth, permissions, API signing, CSRF/security headers, sessions, errors
migrations/    versioned schema changes
models/        Sequelize models + associations
routes/        index (composition), apiRoutes (/api/v1), auditRoutes (dashboard)
services/      business logic (ingestion, integrity, alerts, investigations, QA, reports, …)
utils/         pure helpers (validator, normalizer, integrity, rule engine, diff, csv, …)
views/         .xian templates
public/        css, js, favicon
scripts/       setup, simulator, dev credential
clients/       reference client SDK
__tests__/     unit + integration tests
```

## Integration status

MediSentinel's ingestion API, authentication, validation and monitoring are implemented and covered by automated tests that use a test source system. **PharmaCore POS and the Inventory Management System are registered but not yet connected.** Their teams must add a client (see the integration guide), configure the credentials an administrator issues, and confirm on **Quality Assurance → Event coverage** that their expected events show as *Verified*.

The POS Audit Event Registry (customers, store settings, branches, products, transactions, void authorization, reports and price checks) is implemented on the MediSentinel side. It is tested only with test source systems and the simulator: **no PharmaCore POS code has been changed and no live POS events have been received.** The event contract for the POS team is in [docs/API_INTEGRATION.md §4](docs/API_INTEGRATION.md).
