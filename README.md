# Aftermark

An evidence-driven incident response backend. An incident cannot be closed just because somebody changes a status field: it needs containment evidence and two independent credential holders approving the exact current evidence manifest.

**TypeScript · Fastify · Bun · Zod · Cloudflare D1 · OpenAPI**

## What makes it different

- **Evidence-bound approval:** canonical SHA-256 manifests cover incident details and every evidence reference. New evidence makes old approvals stale without deleting the original attestations.
- **Guarded workflow:** `open → investigating → contained → resolved`. Containment requires evidence; resolution requires two non-creator principals approving the current manifest. Closed incidents are immutable.
- **Verifiable incident history:** each mutation adds a hash-linked event. SQL triggers reject event updates/deletes. Verification checks sequence continuity, hash integrity, and missing tails through a fixed incident revision.
- **Transactional concurrency control:** every mutation must claim a unique next revision. Conflicting writers roll back their entire D1 batch, including evidence, approvals, and events.
- **Tenant isolation:** every resource query is workspace-scoped. Unknown and other-workspace incident IDs both return 404.

## Completed features

Workspace bootstrap; administrator/responder/observer roles; expiring and revocable API keys; server-side peppered key digests; incident creation and cursor feeds; evidence references; independent approval gates; incident exports; dashboard aggregates; audit pagination and verification; generated request schemas and interactive OpenAPI documentation; request IDs; sanitized errors; credential log redaction; CORS allowlists; security headers; body limits; per-process rate limits; migration checksums; graceful shutdown; Docker packaging; GitHub Actions checks; integration tests.

No frontend is included. This repository intentionally prioritizes backend invariants over a large number of shallow CRUD endpoints.

## Requirements and hosting

- Bun **1.4.4** is the tested and CI-pinned runtime.
- A Cloudflare account, a D1 database, and a server-side API token with D1 write permission scoped to that account.
- A Bun-capable host: a Linux VM, a container service, Railway, Render, or similar.

**The Fastify server requires a Bun-capable host, not Cloudflare Workers/Pages.** D1 is used remotely as persistent storage via the Cloudflare REST API.

## Quick start

```sh
bun install --frozen-lockfile
cp .env.example .env
```

Create a D1 database in the Cloudflare dashboard. Fill in `.env`:

| Variable | Purpose |
| --- | --- |
| `BOOTSTRAP_TOKEN` | Operator-only secret, at least 32 characters |
| `API_KEY_PEPPER` | Independent secret used to HMAC stored API keys, at least 32 characters |
| `CF_ACCOUNT_ID` | 32-character Cloudflare account ID |
| `CF_D1_DATABASE_ID` | D1 database UUID |
| `CF_D1_TOKEN` | Server-only, account-scoped D1 API token |
| `NODE_ENV` | `development`, `test`, or `production` |
| `PORT`, `HOST` | Defaults: `3000`, `0.0.0.0` |
| `LOG_LEVEL` | Defaults to `info`; tests use `silent` |
| `CORS_ORIGINS` | Comma-separated exact browser origins; empty disables cross-origin access |

Generate the bootstrap token and pepper separately with `openssl rand -hex 32`. Never reuse them, include credentials in URLs, or commit `.env`. Bun loads `.env` automatically when running these scripts.

```sh
bun run db:migrate
bun run dev
# For a non-watch process:
bun run build
bun dist/server.js
```

Migrations run explicitly, not at web-server startup. The runner records migration checksums and refuses to silently accept an edited, already-applied migration. Run one migration job at a time.

## Entry points and endpoint reference

Local base URL: **http://localhost:3000** (only while the server is running).

Production URL: **not deployed**. Intended repository: **`devnishantt/aftermark`**; publication is pending.

| Method | Path | Access / parameters |
| --- | --- | --- |
| GET | `/` | API discovery |
| GET | `/health/live` | Process liveness; rate-limit exempt |
| GET | `/health/ready` | D1 connectivity and migrated schema readiness |
| GET | `/docs/` | Interactive API documentation |
| GET | `/openapi.json` | Generated OpenAPI document |
| POST | `/v1/workspaces` | Operator bootstrap token; `{name}`; returns initial admin key once |
| GET | `/v1/me` | Current credential's identity and role |
| GET | `/v1/keys` | Admin; latest 200 credential metadata rows, never key digests |
| POST | `/v1/keys` | Admin; `{label, role, expiresInDays?}`; default 30 days, maximum 365 |
| DELETE | `/v1/keys/:id` | Admin; revoke another key; protects the last active admin |
| GET | `/v1/incidents` | `limit` (1–100), `cursor`, `state`, `severity` |
| POST | `/v1/incidents` | Admin/responder; `{title, summary, severity}` |
| GET | `/v1/incidents/:id` | Current incident and revision |
| GET | `/v1/insights` | Workspace counts grouped by state and severity |
| POST | `/v1/incidents/:id/transitions` | Admin/responder; `{expectedRevision, state, reason}` |
| GET | `/v1/incidents/:id/evidence` | Evidence references, maximum 1000 per incident |
| POST | `/v1/incidents/:id/evidence` | Admin/responder; `{expectedRevision, label, uri, sha256, mediaType}` |
| GET | `/v1/incidents/:id/manifest` | Canonical manifest and SHA-256 fingerprint |
| GET | `/v1/incidents/:id/gate` | Allowed next state, approval counts, stale approvals, closure readiness |
| GET | `/v1/incidents/:id/approvals` | Historical manifest-specific attestations |
| POST | `/v1/incidents/:id/approvals` | Non-creator admin/responder; `{expectedRevision, manifestHash, note}` |
| GET | `/v1/incidents/:id/audit` | `after` sequence (default -1), `limit` (1–100) |
| GET | `/v1/incidents/:id/audit/verify` | Verify through a fixed revision; returns the head hash |
| GET | `/v1/incidents/:id/export` | Revision-consistent JSON manifest, attestations, and audit checkpoint |

All `/v1` routes except workspace bootstrap require `Authorization: Bearer <workspace-api-key>`. Observers have read-only access, excluding administrative key listings. UUIDs are required for path IDs. Inputs reject unknown fields. Secrets and API responses use `Cache-Control: no-store`.

### First request

With the server running, from a shell with `BOOTSTRAP_TOKEN` exported:

```sh
curl -sS http://localhost:3000/v1/workspaces \
  -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Release Operations"}'
```

Store the returned `apiKey.key` securely. It is returned only once. Use it to issue individual responder and observer credentials. The initial administrator key expires after 30 days; rotate before expiration. Use a different administrator key to revoke an old administrator credential.

Open an incident, move it to investigation, attach evidence, and contain it. Have two non-creator principals fetch the manifest and approve its hash. Then resolve the incident. Mutations increment `revision`; send its latest value as `expectedRevision`.

```sh
curl -sS http://localhost:3000/v1/incidents \
  -H "Authorization: Bearer $WORKSPACE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Unexpected signing-key use","summary":"Signing activity occurred outside the release window.","severity":"critical"}'
```

### Complete demonstration

```sh
API_URL=http://localhost:3000 bun run demo
```

This reads `BOOTSTRAP_TOKEN` from `.env`, creates a new demo workspace and two reviewer credentials, completes the workflow, and prints IDs plus the verified checkpoint. It does **not** print credentials. Its example evidence URI and digest are illustrative; no real artifact is fetched. It creates persistent records, so use a dedicated development database. It is not a substitute for independent human reviews.

### Concurrency and error handling

A stale revision or a losing concurrent write returns 409. Refetch the incident and deliberately decide whether to retry. D1 write requests are never retried automatically: a network timeout may occur after a successful commit. Check the incident/audit log before retrying an ambiguous write.

```json
{
  "error": {
    "code": "REVISION_CONFLICT",
    "message": "Refetch the incident and retry deliberately with its current revision",
    "requestId": "..."
  }
}
```

Clients should branch on status/code, not human-readable messages. Responses also carry `X-Request-Id`.

## Data architecture

| Table | Responsibility |
| --- | --- |
| `workspaces` | Tenant boundary |
| `api_keys` | Hashed credentials, roles, expiry, revocation |
| `incidents` | Current state and revision |
| `incident_revisions` | Unique revision claims used as atomic concurrency fences |
| `evidence` | Immutable metadata references and artifact digests |
| `approvals` | Distinct principal + manifest attestations |
| `audit_events` | Ordered canonical payloads, previous hashes, event hashes |
| `schema_migrations` | Applied migration names and checksums |

Storage: **Cloudflare D1 only** in production. The D1 REST `batch` form provides the transaction boundary. Every domain mutation claims a revision, updates its records, advances the incident, and appends its event in the same batch. No application data is stored in process memory or local files in production. The rate-limit plugin uses ephemeral process-local counters, not durable storage.

Tests use an in-memory SQLite adapter as a test double, with real constraints and transactions. That adapter is not imported by the production entry point or bundle.

## Security model and limits

- Approval independence means **distinct API-key principals**, not verified distinct humans. An administrator can issue multiple keys; map each key to a separately controlled identity operationally. Human identity/SSO enforcement is a future feature.
- Approval records remain historical attestations after a key is revoked or expires. Revocation prevents future API access; it does not retroactively erase reviews.
- Evidence is a metadata reference. The server never downloads the URI, eliminating a server-side fetch/SSRF path. It cannot prove that a supplied digest matches remote bytes. Do not put expiring signed URLs or credentials inside evidence URIs; URI metadata is visible to workspace readers.
- A hash chain is tamper-evident, **not tamper-proof or digitally signed**. A privileged database operator could drop triggers and rewrite all records/hashes. Export head hashes to independently controlled, append-only storage to detect whole-history rewrites. The verifier validates the event chain, not the actual bytes of external evidence or a reconstruction of every domain table.
- Protect `/v1/workspaces` at your reverse proxy and keep its bootstrap token operator-only. Browser clients must never receive the D1 token, pepper, or bootstrap token.
- `trustProxy` is deliberately false. Configure explicit trusted proxy addresses before relying on forwarded IPs. Process-local limits are 120 requests/minute/IP globally and 5 bootstrap requests/minute/IP. Enforce fleet-wide quotas at the ingress when running replicas. Clients behind a shared proxy otherwise share its budget.
- Rotate workspace admin credentials before expiry. There is no account-recovery endpoint for an expired last admin. Preserve a securely managed, rotating operator credential or plan a controlled database recovery procedure.
- Keep HTTPS at the ingress. Public health/docs expose route shapes, not tenant data. A 64 KiB body limit and strict schemas constrain input size. CORS is not authentication.
- The remote D1 API adds network latency and control-plane limits. Large-scale production use needs load tests, upstream budget monitoring, and possibly a dedicated data-access Worker. This is not a claim of production certification.

## Development and verification

```sh
bun run typecheck
bun test
bun run test:coverage
bun run build
# All three main checks:
bun run check
```

Verified locally: **44 passing tests**, strict TypeScript checks, production Bun build, and zero known vulnerabilities from `npm audit --omit=dev` at the time of the build. A loopback HTTP smoke test exercised health, readiness, and generated OpenAPI through PM2. The complete demonstration also ran successfully against that ephemeral test service, resolving an incident at revision 6 with seven verified audit events. Coverage applies to imported/tested modules; it does not prove live D1 behavior, container runtime behavior, or startup/signal-path coverage.

Tests cover tenant/resource isolation, key expiry and revocation, unauthorized roles, input limits, CORS, rate limiting, duplicate evidence, cursor feeds, transaction rollback, concurrent writes, stale approvals, independent closure gates, immutable audit triggers, altered events, missing tails, and exports. D1 transport tests verify request shapes, redacted errors, and no automatic mutation retries.

Optional loopback-only network smoke test (development dependencies and PM2 required):

```sh
bun run build
pm2 start tests/ecosystem.config.cjs
curl --fail http://127.0.0.1:3000/health/ready
pm2 delete aftermark-smoke
```

The test PM2 configuration resolves the project root from its own location. Never use the smoke server as a production deployment.

## Container deployment

```sh
docker build -t aftermark .
# .env must contain NODE_ENV=production and your real server-side secrets.
docker run --rm --env-file .env -p 3000:3000 aftermark
```

Run `bun run db:migrate` from the source checkout before deploying a new version. The image runs as an unprivileged user, contains production dependencies and an external-package Bun build, and has a readiness healthcheck. Supply secrets through the host's secret manager in production, not an image layer. SIGTERM/SIGINT drain Fastify connections with a 15-second deadline.

GitHub Actions is configured to install the frozen Bun lockfile, typecheck, run coverage, build, and build the container. **The container has not been built locally because Docker was unavailable.** No live D1 database, remote integration test, GitHub Actions run, or production deployment has been performed.

## Not implemented / next steps

1. Validate against a real D1 database and benchmark REST latency and contention.
2. Enforce distinct human reviewers through OIDC/SSO and organization membership.
3. Anchor audit checkpoints in independently controlled append-only storage.
4. Add authenticated artifact uploads, byte-level digest verification, and retention policies.
5. Add distributed ingress quotas, observability/alerting, and operational recovery procedures.
6. Add idempotency keys, notifications, webhook delivery, and automated retention jobs only with durable backing.
7. Add a reviewer UI if needed; no UI, file uploads, background worker, or external integrations are implied by the current API.

## History provenance

The **16 implementation commits** use assigned historical timestamps on **October 28–29, 2026 (UTC), eight commits per day**, at the repository owner's request. These timestamps are organizational metadata, not a record of when development actually occurred. Each commit represents a concrete implementation step.
