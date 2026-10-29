import { sha256 } from '../src/core/crypto'

const base = process.env.API_URL ?? 'http://localhost:3000'
const bootstrap = process.env.BOOTSTRAP_TOKEN
if (!bootstrap) throw new Error('BOOTSTRAP_TOKEN is required')
if (!['http:', 'https:'].includes(new URL(base).protocol)) throw new Error('API_URL must be HTTP(S)')

async function call(method: string, path: string, token: string, body?: object) {
  const response = await fetch(new URL(path, base), {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(15_000),
  })
  const data = await response.json()
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${JSON.stringify(data)}`)
  return data
}

// This intentionally creates persistent demo records. Never run against an
// unrelated production workspace. Credentials are not printed or persisted.
const workspace = await call('POST', '/v1/workspaces', bootstrap, { name: 'Aftermark demonstration' })
const admin: string = workspace.apiKey.key
const reviewers = []
for (const label of ['Primary reviewer', 'Independent reviewer']) {
  reviewers.push(await call('POST', '/v1/keys', admin, { label, role: 'responder', expiresInDays: 1 }))
}
const incident = await call('POST', '/v1/incidents', admin, { title: 'Unexpected signing-key activity', summary: 'A release signing key appeared outside the approved deployment window.', severity: 'critical' })
const path = `/v1/incidents/${incident.id}`
await call('POST', `${path}/transitions`, admin, { expectedRevision: 0, state: 'investigating', reason: 'Investigating the release signature trail.' })
await call('POST', `${path}/evidence`, admin, { expectedRevision: 1, label: 'Example release log reference', uri: 'https://example.com/release-log.json', sha256: sha256('demonstration-log-content'), mediaType: 'application/json' })
await call('POST', `${path}/transitions`, admin, { expectedRevision: 2, state: 'contained', reason: 'Signing key revoked and release pipeline isolated.' })
const { manifestHash } = await call('GET', `${path}/manifest`, admin)
for (const [index, reviewer] of reviewers.entries()) {
  await call('POST', `${path}/approvals`, reviewer.key, { expectedRevision: 3 + index, manifestHash, note: 'Evidence manifest reviewed; containment appears complete.' })
}
await call('POST', `${path}/transitions`, admin, { expectedRevision: 5, state: 'resolved', reason: 'Both independent review credentials have approved.' })
const verification = await call('GET', `${path}/audit/verify`, admin)
console.log(JSON.stringify({ workspaceId: workspace.workspace.id, incidentId: incident.id, state: 'resolved', verification }, null, 2))
console.log('Demo keys are ephemeral to this process. Retain a separate operator key for real usage.')
