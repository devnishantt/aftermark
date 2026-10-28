import { z } from 'zod'
import { newId, now } from '../core/crypto'
import { AppError, assert } from '../core/errors'
import { first, type Database, type Scalar, type Statement } from '../db/database'
import { AuditService, GENESIS } from './audit'
import { incidentInput, incidentQuery, type Incident, type Principal } from './schemas'

const cursorSchema = z.strictObject({ at: z.iso.datetime(), id: z.uuid() })

export class IncidentService {
  readonly audit: AuditService
  constructor(readonly db: Database) { this.audit = new AuditService(db) }

  async get(principal: Principal, id: string): Promise<Incident> {
    const incident = await first<Incident>(this.db, 'SELECT * FROM incidents WHERE workspace_id = ? AND id = ?', [principal.workspaceId, id])
    // Return the same response for nonexistent and other tenants' records.
    assert(incident, 404, 'NOT_FOUND', 'Incident not found')
    return incident
  }

  async create(principal: Principal, data: z.infer<typeof incidentInput>) {
    const id = newId(), created = now()
    await this.db.batch([
      { sql: 'INSERT INTO incidents (id, workspace_id, title, summary, severity, state, created_by, revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)', params: [id, principal.workspaceId, data.title, data.summary, data.severity, 'open', principal.id, created, created] },
      { sql: 'INSERT INTO incident_revisions (workspace_id, incident_id, revision) VALUES (?, ?, 0)', params: [principal.workspaceId, id] },
      this.audit.append(principal, id, 0, 'incident.created', data, GENESIS),
    ])
    return this.get(principal, id)
  }

  async list(principal: Principal, query: z.infer<typeof incidentQuery>) {
    const where = ['workspace_id = ?'], params: Scalar[] = [principal.workspaceId]
    if (query.state) { where.push('state = ?'); params.push(query.state) }
    if (query.severity) { where.push('severity = ?'); params.push(query.severity) }
    if (query.cursor) {
      let cursor: z.infer<typeof cursorSchema>
      try { cursor = cursorSchema.parse(JSON.parse(Buffer.from(query.cursor, 'base64url').toString('utf8'))) }
      catch { throw new AppError(400, 'INVALID_CURSOR', 'Cursor is not valid') }
      where.push('(created_at < ? OR (created_at = ? AND id < ?))')
      params.push(cursor.at, cursor.at, cursor.id)
    }
    params.push(query.limit + 1)
    const rows = await this.db.all<Incident>(`SELECT * FROM incidents WHERE ${where.join(' AND ')} ORDER BY created_at DESC, id DESC LIMIT ?`, params)
    const items = rows.slice(0, query.limit), last = items.at(-1)
    return {
      items,
      nextCursor: rows.length > query.limit && last ? Buffer.from(JSON.stringify({ at: last.created_at, id: last.id })).toString('base64url') : null,
    }
  }

  async checkRevision(principal: Principal, id: string, expected: number) {
    const incident = await this.get(principal, id)
    assert(incident.revision === expected, 409, 'REVISION_CONFLICT', 'Refetch the incident and retry deliberately with its current revision')
    assert(incident.state !== 'resolved', 409, 'INCIDENT_CLOSED', 'Resolved incidents are immutable')
    return incident
  }

  async mutate(principal: Principal, incident: Incident, action: string, payload: unknown, statements: Statement[]) {
    const head = await this.audit.head(principal, incident.id)
    assert(head && head.sequence === incident.revision, 409, 'REVISION_CONFLICT', 'Incident changed while processing this request')
    // The unique revision insert is first. A losing concurrent writer rolls back
    // every following write, including its audit event and evidence/approval rows.
    await this.db.batch([
      { sql: 'INSERT INTO incident_revisions (workspace_id, incident_id, revision) VALUES (?, ?, ?)', params: [principal.workspaceId, incident.id, incident.revision + 1] },
      ...statements,
      { sql: 'UPDATE incidents SET revision = ?, updated_at = ? WHERE workspace_id = ? AND id = ?', params: [incident.revision + 1, now(), principal.workspaceId, incident.id] },
      this.audit.append(principal, incident.id, incident.revision + 1, action, payload, head.hash),
    ])
    return this.get(principal, incident.id)
  }

  async summary(principal: Principal) {
    return this.db.all<{ state: string; severity: string; count: number }>('SELECT state, severity, COUNT(*) AS count FROM incidents WHERE workspace_id = ? GROUP BY state, severity ORDER BY state, severity', [principal.workspaceId])
  }
}
