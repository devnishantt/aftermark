import type { FastifyInstance } from 'fastify'
import type { ZodTypeProvider } from 'fastify-type-provider-zod'
import type { Config } from '../core/config'
import type { Database } from '../db/database'
import { EvidenceService } from './evidence'
import { IdentityService } from './identity'
import { IncidentService } from './incidents'
import { WorkflowService } from './workflow'
import { approvalInput, eventQuery, evidenceInput, incidentInput, incidentParams, incidentQuery, keyInput, keyParams, transitionInput, workspaceInput } from './schemas'

export async function registerRoutes(app: FastifyInstance, db: Database, config: Config) {
  const identity = new IdentityService(db, config), incidents = new IncidentService(db)
  const evidence = new EvidenceService(incidents), workflow = new WorkflowService(incidents, evidence)
  const api = app.withTypeProvider<ZodTypeProvider>()
  const protectedSchema = { security: [{ bearerAuth: [] }] }

  api.post('/v1/workspaces', {
    schema: { tags: ['Workspaces'], summary: 'Bootstrap a workspace; returns its administrator key once', security: [{ bootstrapAuth: [] }], body: workspaceInput },
    onRequest: async request => identity.bootstrap(request.headers.authorization),
    config: { rateLimit: { max: 5, timeWindow: '1 minute' } },
  }, async (request, reply) => {
    reply.header('Cache-Control', 'no-store')
    return reply.code(201).send(await identity.createWorkspace(request.body))
  })

  await app.register(async protectedApp => {
    protectedApp.addHook('onRequest', request => identity.authenticate(request))
    const routes = protectedApp.withTypeProvider<ZodTypeProvider>()
    const reader = (request: Parameters<typeof identity.require>[0]) => identity.require(request, ['admin', 'responder', 'observer'])
    const writer = (request: Parameters<typeof identity.require>[0]) => identity.require(request, ['admin', 'responder'])
    const admin = (request: Parameters<typeof identity.require>[0]) => identity.require(request, ['admin'])

    routes.get('/v1/me', { schema: { ...protectedSchema, tags: ['Workspaces'], summary: 'Inspect the authenticated principal' } }, async request => reader(request))
    routes.get('/v1/keys', { schema: { ...protectedSchema, tags: ['Keys'], summary: 'List credential metadata without secret digests' } }, async request => ({ items: await identity.listKeys(admin(request)) }))
    routes.post('/v1/keys', { schema: { ...protectedSchema, tags: ['Keys'], summary: 'Issue a key; returned only once', body: keyInput } }, async (request, reply) => {
      reply.header('Cache-Control', 'no-store')
      return reply.code(201).send(await identity.createKey(admin(request), request.body))
    })
    routes.delete('/v1/keys/:id', { schema: { ...protectedSchema, tags: ['Keys'], summary: 'Revoke a credential', params: keyParams } }, async (request, reply) => {
      await identity.revokeKey(admin(request), request.params.id)
      return reply.code(204).send()
    })
    routes.get('/v1/incidents', { schema: { ...protectedSchema, tags: ['Incidents'], summary: 'Cursor-paginated tenant incident feed', querystring: incidentQuery } }, async request => incidents.list(reader(request), request.query))
    routes.post('/v1/incidents', { schema: { ...protectedSchema, tags: ['Incidents'], summary: 'Open an incident', body: incidentInput } }, async (request, reply) => {
      const incident = await incidents.create(writer(request), request.body)
      return reply.code(201).header('Location', `/v1/incidents/${incident.id}`).send(incident)
    })
    routes.get('/v1/insights', { schema: { ...protectedSchema, tags: ['Incidents'], summary: 'Counts by state and severity' } }, async request => ({ items: await incidents.summary(reader(request)) }))
    routes.get('/v1/incidents/:id', { schema: { ...protectedSchema, tags: ['Incidents'], summary: 'Read current incident revision', params: incidentParams } }, async request => incidents.get(reader(request), request.params.id))
    routes.post('/v1/incidents/:id/transitions', { schema: { ...protectedSchema, tags: ['Workflow'], summary: 'Move through guarded incident states', params: incidentParams, body: transitionInput } }, async request => workflow.transition(writer(request), request.params.id, request.body))
    routes.get('/v1/incidents/:id/evidence', { schema: { ...protectedSchema, tags: ['Evidence'], summary: 'List immutable artifact references', params: incidentParams } }, async request => ({ items: await evidence.list(reader(request), request.params.id) }))
    routes.post('/v1/incidents/:id/evidence', { schema: { ...protectedSchema, tags: ['Evidence'], summary: 'Attach evidence metadata without fetching the URI', params: incidentParams, body: evidenceInput } }, async (request, reply) => reply.code(201).send(await evidence.add(writer(request), request.params.id, request.body)))
    routes.get('/v1/incidents/:id/manifest', { schema: { ...protectedSchema, tags: ['Evidence'], summary: 'Export evidence and its canonical fingerprint', params: incidentParams } }, async request => {
      const principal = reader(request)
      return evidence.manifest(principal, await incidents.get(principal, request.params.id))
    })
    routes.get('/v1/incidents/:id/gate', { schema: { ...protectedSchema, tags: ['Workflow'], summary: 'Inspect approval readiness and stale approvals', params: incidentParams } }, async request => {
      const principal = reader(request)
      return workflow.gate(principal, await incidents.get(principal, request.params.id))
    })
    routes.get('/v1/incidents/:id/approvals', { schema: { ...protectedSchema, tags: ['Workflow'], summary: 'List manifest-specific attestations', params: incidentParams } }, async request => ({ items: await workflow.approvals(reader(request), request.params.id) }))
    routes.post('/v1/incidents/:id/approvals', { schema: { ...protectedSchema, tags: ['Workflow'], summary: 'Approve a reviewed manifest independently', params: incidentParams, body: approvalInput } }, async (request, reply) => reply.code(201).send(await workflow.approve(writer(request), request.params.id, request.body)))
    routes.get('/v1/incidents/:id/audit', { schema: { ...protectedSchema, tags: ['Audit'], summary: 'Read an ordered audit page', params: incidentParams, querystring: eventQuery } }, async request => {
      const principal = reader(request)
      await incidents.get(principal, request.params.id)
      const items = await incidents.audit.list(principal, request.params.id, request.query.after, request.query.limit)
      return { items, nextAfter: items.at(-1)?.sequence ?? request.query.after }
    })
    routes.get('/v1/incidents/:id/audit/verify', { schema: { ...protectedSchema, tags: ['Audit'], summary: 'Verify the chain through a fixed incident revision', params: incidentParams } }, async request => {
      const principal = reader(request), incident = await incidents.get(principal, request.params.id)
      return { incidentId: incident.id, revision: incident.revision, ...await incidents.audit.verify(principal, incident.id, incident.revision) }
    })
    routes.get('/v1/incidents/:id/export', { schema: { ...protectedSchema, tags: ['Audit'], summary: 'Export a revision-consistent manifest, approvals, and audit checkpoint', params: incidentParams } }, async (request, reply) => {
      const principal = reader(request), incident = await incidents.get(principal, request.params.id)
      const manifest = await evidence.manifest(principal, incident)
      const approvals = await workflow.approvals(principal, incident.id)
      const verification = await incidents.audit.verify(principal, incident.id, incident.revision)
      const current = await incidents.get(principal, incident.id)
      if (current.revision !== incident.revision) return reply.code(409).send({ error: { code: 'REVISION_CONFLICT', message: 'Incident changed during export', requestId: request.id } })
      return reply.header('Content-Disposition', `attachment; filename="aftermark-${incident.id}.json"`).send({ incident, ...manifest, approvals, verification })
    })
  })
}
