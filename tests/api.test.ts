import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { sha256 } from '../src/core/crypto'
import { fixture, testConfig } from './helpers'

let f: Awaited<ReturnType<typeof fixture>>
let admin: string
beforeEach(async () => { f = await fixture(); admin = (await f.workspace()).apiKey.key })
afterEach(async () => { await f.close() })
const artifact = (revision: number, suffix = 'first') => ({ expectedRevision: revision, label: `Release log ${suffix}`, uri: `https://evidence.example.com/${suffix}.json`, sha256: sha256(suffix), mediaType: 'application/json' })

async function contained() {
  const incident = await f.incident(admin), base = `/v1/incidents/${incident.id}`
  expect((await f.request('POST', `${base}/transitions`, admin, { expectedRevision: 0, state: 'investigating', reason: 'Responder has started triage.' })).statusCode).toBe(200)
  expect((await f.request('POST', `${base}/evidence`, admin, artifact(1))).statusCode).toBe(201)
  expect((await f.request('POST', `${base}/transitions`, admin, { expectedRevision: 2, state: 'contained', reason: 'Signing key isolated and rotated.' })).statusCode).toBe(200)
  return { id: incident.id, base, revision: 3 }
}

describe('HTTP operations and validation', () => {
  test('serves health, docs and OpenAPI with bearer security', async () => {
    expect((await f.request('GET', '/health/live')).json()).toEqual({ status: 'ok' })
    expect((await f.request('GET', '/health/ready')).statusCode).toBe(200)
    expect((await f.request('GET', '/docs/')).statusCode).toBe(200)
    const spec = (await f.request('GET', '/openapi.json')).json()
    expect(spec.paths['/v1/incidents'].post.requestBody).toBeDefined()
    expect(spec.components.securitySchemes.bearerAuth.scheme).toBe('bearer')
  })
  test('requires credentials and emits a traceable error envelope', async () => {
    const response = await f.request('GET', '/v1/incidents')
    expect(response.statusCode).toBe(401)
    expect(response.headers['www-authenticate']).toBe('Bearer')
    expect(response.headers['x-request-id']).toBe(response.json().error.requestId)
  })
  test('rejects unknown fields, invalid enums and short summaries', async () => {
    for (const body of [
      { title: 'Valid title', summary: 'A sufficiently long summary.', severity: 'catastrophic' },
      { title: 'Valid title', summary: 'short', severity: 'high' },
      { title: 'Valid title', summary: 'A sufficiently long summary.', severity: 'high', workspace_id: 'injected' },
    ]) expect((await f.request('POST', '/v1/incidents', admin, body)).statusCode).toBe(400)
  })
  test('rejects malformed JSON without exposing parser diagnostics', async () => {
    const response = await f.app.inject({ method: 'POST', url: '/v1/incidents', headers: { authorization: `Bearer ${admin}`, 'content-type': 'application/json' }, payload: '{invalid' })
    expect(response.statusCode).toBe(400)
    expect(response.body).not.toContain('SyntaxError')
  })
  test('rejects oversized payloads', async () => {
    expect((await f.request('POST', '/v1/incidents', admin, { summary: 'x'.repeat(70_000) })).statusCode).toBe(413)
  })
  test('sets security headers and disables caching for API data', async () => {
    const response = await f.request('GET', '/v1/me', admin)
    expect(response.headers['x-content-type-options']).toBe('nosniff')
    expect(response.headers['cache-control']).toBe('no-store')
  })
  test('only permits configured browser origins', async () => {
    const allowed = await f.app.inject({ url: '/health/live', headers: { origin: 'https://console.example.com' } })
    const denied = await f.app.inject({ url: '/health/live', headers: { origin: 'https://evil.example.com' } })
    expect(allowed.headers['access-control-allow-origin']).toBe('https://console.example.com')
    expect(denied.headers['access-control-allow-origin']).toBeUndefined()
  })
  test('rate limits the privileged bootstrap route', async () => {
    // The fixture has already issued one bootstrap request from this IP.
    for (let n = 0; n < 4; n++) expect((await f.request('POST', '/v1/workspaces', testConfig.BOOTSTRAP_TOKEN, { name: `Workspace ${n}` })).statusCode).toBe(201)
    expect((await f.request('POST', '/v1/workspaces', testConfig.BOOTSTRAP_TOKEN, { name: 'Overflow' })).statusCode).toBe(429)
  })
  test('returns sanitized not-found and storage errors', async () => {
    expect((await f.request('GET', '/not-a-route')).json().error.code).toBe('NOT_FOUND')
    f.db.failNextBatch = true
    const response = await f.request('POST', '/v1/incidents', admin, { title: 'Incident failure', summary: 'A sufficiently long summary.', severity: 'low' })
    expect(response.statusCode).toBe(503)
    expect(response.body).not.toContain('Injected')
  })
})

describe('identity and tenant isolation', () => {
  test('requires operator bootstrap authorization', async () => {
    expect((await f.request('POST', '/v1/workspaces', admin, { name: 'Invalid operator' })).statusCode).toBe(401)
  })
  test('stores only peppered key digests and never lists credentials', async () => {
    const key = await f.key(admin)
    const row = f.db.raw.query('SELECT digest FROM api_keys WHERE id = ?').get(key.id) as { digest: string }
    expect(row.digest).toHaveLength(64)
    expect(row.digest).not.toContain(key.key)
    const response = await f.request('GET', '/v1/keys', admin)
    expect(response.body).not.toContain(key.key)
    expect(response.body).not.toContain(row.digest)
  })
  test('observer can read but cannot mutate or issue keys', async () => {
    const observer = await f.key(admin, 'observer')
    expect((await f.request('GET', '/v1/incidents', observer.key)).statusCode).toBe(200)
    expect((await f.request('POST', '/v1/incidents', observer.key, { title: 'Valid incident', summary: 'An incident summary for review.', severity: 'low' })).statusCode).toBe(403)
    expect((await f.request('POST', '/v1/keys', observer.key, { label: 'Escalation', role: 'admin' })).statusCode).toBe(403)
    expect((await f.request('GET', '/v1/keys', observer.key)).statusCode).toBe(403)
  })
  test('revoked and expired credentials cannot authenticate', async () => {
    const revoked = await f.key(admin), expired = await f.key(admin)
    expect((await f.request('DELETE', `/v1/keys/${revoked.id}`, admin)).statusCode).toBe(204)
    expect((await f.request('GET', '/v1/me', revoked.key)).statusCode).toBe(401)
    f.db.raw.query('UPDATE api_keys SET expires_at = ? WHERE id = ?').run('2000-01-01T00:00:00.000Z', expired.id)
    expect((await f.request('GET', '/v1/me', expired.key)).statusCode).toBe(401)
  })
  test('prevents self revocation and permits administrator rotation', async () => {
    const me = (await f.request('GET', '/v1/me', admin)).json()
    expect((await f.request('DELETE', `/v1/keys/${me.id}`, admin)).statusCode).toBe(409)
    const replacement = await f.key(admin, 'admin')
    expect((await f.request('DELETE', `/v1/keys/${me.id}`, replacement.key)).statusCode).toBe(204)
    expect((await f.request('GET', '/v1/me', admin)).statusCode).toBe(401)
  })
  test('hides another tenants incident and every child resource', async () => {
    const incident = await f.incident(admin), other = await f.workspace('Other tenant')
    for (const suffix of ['', '/evidence', '/manifest', '/gate', '/approvals', '/audit', '/audit/verify', '/export']) {
      expect((await f.request('GET', `/v1/incidents/${incident.id}${suffix}`, other.apiKey.key)).statusCode).toBe(404)
    }
    expect((await f.request('GET', '/v1/incidents', other.apiKey.key)).json().items).toHaveLength(0)
    expect((await f.request('GET', '/v1/insights', other.apiKey.key)).json().items).toHaveLength(0)
  })
  test('cannot attach evidence or revoke credentials across tenants', async () => {
    const incident = await f.incident(admin), other = await f.workspace('Other tenant')
    expect((await f.request('POST', `/v1/incidents/${incident.id}/evidence`, other.apiKey.key, artifact(0))).statusCode).toBe(404)
    const key = await f.key(admin)
    expect((await f.request('DELETE', `/v1/keys/${key.id}`, other.apiKey.key)).statusCode).toBe(409)
    expect((await f.request('GET', '/v1/me', key.key)).statusCode).toBe(200)
  })
})

describe('incident feed and revision concurrency', () => {
  test('paginates deterministically without duplicates', async () => {
    for (let n = 0; n < 5; n++) await f.incident(admin)
    let cursor: string | null = null
    const ids: string[] = []
    do {
      const page: { items: { id: string }[]; nextCursor: string | null } = (await f.request('GET', `/v1/incidents?limit=2${cursor ? `&cursor=${cursor}` : ''}`, admin)).json()
      ids.push(...page.items.map((item: { id: string }) => item.id))
      cursor = page.nextCursor
    } while (cursor)
    expect(ids).toHaveLength(5)
    expect(new Set(ids).size).toBe(5)
  })
  test('filters severity and state and rejects invalid cursors', async () => {
    await f.incident(admin)
    expect((await f.request('GET', '/v1/incidents?severity=low', admin)).json().items).toHaveLength(0)
    expect((await f.request('GET', '/v1/incidents?state=open', admin)).json().items).toHaveLength(1)
    expect((await f.request('GET', '/v1/incidents?cursor=not-json', admin)).statusCode).toBe(400)
    expect((await f.request('GET', '/v1/incidents?limit=101', admin)).statusCode).toBe(400)
  })
  test('reports tenant-scoped summary counts', async () => {
    await f.incident(admin)
    expect((await f.request('GET', '/v1/insights', admin)).json().items).toEqual([{ state: 'open', severity: 'critical', count: 1 }])
  })
  test('rejects stale revisions without side effects', async () => {
    const { base } = await contained()
    const response = await f.request('POST', `${base}/evidence`, admin, artifact(0, 'stale'))
    expect(response.statusCode).toBe(409)
    expect((await f.request('GET', `${base}/evidence`, admin)).json().items).toHaveLength(1)
  })
  test('allows exactly one concurrent mutation for a revision', async () => {
    const incident = await f.incident(admin), base = `/v1/incidents/${incident.id}`
    const results = await Promise.all([
      f.request('POST', `${base}/evidence`, admin, artifact(0, 'a')),
      f.request('POST', `${base}/evidence`, admin, artifact(0, 'b')),
    ])
    expect(results.map(r => r.statusCode).sort()).toEqual([201, 409])
    expect((await f.request('GET', base, admin)).json().revision).toBe(1)
    expect((await f.request('GET', `${base}/evidence`, admin)).json().items).toHaveLength(1)
    expect((await f.request('GET', `${base}/audit/verify`, admin)).json().valid).toBe(true)
  })
  test('rolls back a revision claim after a mid-batch failure', async () => {
    const incident = await f.incident(admin), base = `/v1/incidents/${incident.id}`
    f.db.failNextBatch = true
    expect((await f.request('POST', `${base}/evidence`, admin, artifact(0))).statusCode).toBe(503)
    expect((await f.request('GET', base, admin)).json().revision).toBe(0)
    expect((await f.request('GET', `${base}/evidence`, admin)).json().items).toHaveLength(0)
    expect((await f.request('POST', `${base}/evidence`, admin, artifact(0))).statusCode).toBe(201)
  })
})

describe('evidence and closure gates', () => {
  test('rejects HTTP evidence URIs and duplicate artifact digests', async () => {
    const incident = await f.incident(admin), base = `/v1/incidents/${incident.id}`
    expect((await f.request('POST', `${base}/evidence`, admin, { ...artifact(0), uri: 'http://internal.example/private' })).statusCode).toBe(400)
    expect((await f.request('POST', `${base}/evidence`, admin, artifact(0))).statusCode).toBe(201)
    expect((await f.request('POST', `${base}/evidence`, admin, artifact(1))).statusCode).toBe(409)
  })
  test('cannot skip states or contain without evidence', async () => {
    const incident = await f.incident(admin), base = `/v1/incidents/${incident.id}`
    expect((await f.request('POST', `${base}/transitions`, admin, { expectedRevision: 0, state: 'resolved', reason: 'Attempt to skip all the gates.' })).statusCode).toBe(409)
    await f.request('POST', `${base}/transitions`, admin, { expectedRevision: 0, state: 'investigating', reason: 'Start investigation immediately.' })
    expect((await f.request('POST', `${base}/transitions`, admin, { expectedRevision: 1, state: 'contained', reason: 'Attempt containment without proof.' })).json().error.code).toBe('EVIDENCE_REQUIRED')
  })
  test('creator cannot approve and uncontained incidents cannot be approved', async () => {
    const incident = await f.incident(admin), responder = await f.key(admin)
    const base = `/v1/incidents/${incident.id}`
    expect((await f.request('POST', `${base}/approvals`, responder.key, { expectedRevision: 0, manifestHash: 'a'.repeat(64), note: 'Reviewed incident evidence carefully.' })).json().error.code).toBe('NOT_CONTAINED')
    const containedIncident = await contained()
    const manifest = (await f.request('GET', `${containedIncident.base}/manifest`, admin)).json()
    expect((await f.request('POST', `${containedIncident.base}/approvals`, admin, { expectedRevision: 3, manifestHash: manifest.manifestHash, note: 'Reviewed incident evidence carefully.' })).statusCode).toBe(403)
  })
  test('requires two distinct approvals for the exact current manifest', async () => {
    const { base } = await contained(), first = await f.key(admin), second = await f.key(admin)
    const manifest = (await f.request('GET', `${base}/manifest`, admin)).json()
    expect((await f.request('POST', `${base}/approvals`, first.key, { expectedRevision: 3, manifestHash: 'b'.repeat(64), note: 'Reviewed a different manifest hash.' })).statusCode).toBe(409)
    expect((await f.request('POST', `${base}/approvals`, first.key, { expectedRevision: 3, manifestHash: manifest.manifestHash, note: 'Containment evidence reviewed independently.' })).statusCode).toBe(201)
    expect((await f.request('POST', `${base}/approvals`, first.key, { expectedRevision: 4, manifestHash: manifest.manifestHash, note: 'Attempted duplicate approval vote.' })).statusCode).toBe(409)
    expect((await f.request('POST', `${base}/transitions`, admin, { expectedRevision: 4, state: 'resolved', reason: 'Only one principal has approved.' })).json().error.code).toBe('APPROVALS_REQUIRED')
    expect((await f.request('POST', `${base}/approvals`, second.key, { expectedRevision: 4, manifestHash: manifest.manifestHash, note: 'Second independent evidence review complete.' })).statusCode).toBe(201)
    expect((await f.request('GET', `${base}/gate`, admin)).json().canResolve).toBe(true)
    expect((await f.request('POST', `${base}/transitions`, admin, { expectedRevision: 5, state: 'resolved', reason: 'Both independent reviewers approved.' })).statusCode).toBe(200)
    expect((await f.request('GET', base, admin)).json().state).toBe('resolved')
    expect((await f.request('POST', `${base}/evidence`, admin, artifact(6, 'too-late'))).json().error.code).toBe('INCIDENT_CLOSED')
    expect((await f.request('GET', `${base}/audit/verify`, admin)).json().verifiedEvents).toBe(7)
  })
  test('new evidence invalidates prior approvals without deleting attestations', async () => {
    const { base } = await contained(), responder = await f.key(admin)
    const original = (await f.request('GET', `${base}/manifest`, admin)).json()
    await f.request('POST', `${base}/approvals`, responder.key, { expectedRevision: 3, manifestHash: original.manifestHash, note: 'Reviewed original evidence manifest.' })
    await f.request('POST', `${base}/evidence`, admin, artifact(4, 'additional'))
    const gate = (await f.request('GET', `${base}/gate`, admin)).json()
    expect(gate.manifestHash).not.toBe(original.manifestHash)
    expect(gate.approverCount).toBe(0)
    expect(gate.staleApprovalCount).toBe(1)
    expect((await f.request('GET', `${base}/approvals`, admin)).json().items).toHaveLength(1)
  })
})

describe('audit chain and exports', () => {
  test('verifies chain continuity and supports ordered event pagination', async () => {
    const { base } = await contained()
    const result = (await f.request('GET', `${base}/audit/verify`, admin)).json()
    expect(result.valid).toBe(true)
    expect(result.verifiedEvents).toBe(4)
    const page = (await f.request('GET', `${base}/audit?after=0&limit=2`, admin)).json()
    expect(page.items.map((item: { sequence: number }) => item.sequence)).toEqual([1, 2])
    expect(page.nextAfter).toBe(2)
  })
  test('database triggers reject audit updates and deletes', async () => {
    const incident = await f.incident(admin)
    expect(() => f.db.raw.query('UPDATE audit_events SET action = ? WHERE incident_id = ?').run('forged', incident.id)).toThrow('immutable')
    expect(() => f.db.raw.query('DELETE FROM audit_events WHERE incident_id = ?').run(incident.id)).toThrow('immutable')
  })
  test('detects malicious corruption when privileged SQL bypasses triggers', async () => {
    const { base, id } = await contained()
    f.db.raw.exec('DROP TRIGGER audit_no_update')
    f.db.raw.query('UPDATE audit_events SET payload = ? WHERE incident_id = ? AND sequence = 1').run('{"tampered":true}', id)
    const result = (await f.request('GET', `${base}/audit/verify`, admin)).json()
    expect(result.valid).toBe(false)
    expect(result.brokenAt).toBe(1)
  })
  test('detects a missing audit tail rather than accepting a valid prefix', async () => {
    const { base, id } = await contained()
    f.db.raw.exec('DROP TRIGGER audit_no_delete')
    f.db.raw.query('DELETE FROM audit_events WHERE incident_id = ? AND sequence = 3').run(id)
    const result = (await f.request('GET', `${base}/audit/verify`, admin)).json()
    expect(result.valid).toBe(false)
    expect(result.brokenAt).toBe(3)
  })
  test('exports evidence, approvals and a verifiable revision checkpoint', async () => {
    const { base } = await contained()
    const response = await f.request('GET', `${base}/export`, admin), data = response.json()
    expect(response.headers['content-disposition']).toContain('attachment; filename=')
    expect(data.incident.revision).toBe(3)
    expect(data.manifest.evidence).toHaveLength(1)
    expect(data.verification.valid).toBe(true)
    expect(data.manifestHash).toHaveLength(64)
    expect(data.verification.head).toHaveLength(64)
  })
})
