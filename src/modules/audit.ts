import { canonical, newId, now, sha256 } from '../core/crypto'
import { first, type Database, type Statement } from '../db/database'
import type { AuditEvent, Principal } from './schemas'

export const GENESIS = '0'.repeat(64)
export const eventHash = (event: Omit<AuditEvent, 'hash'>): string => sha256(canonical(event))

export class AuditService {
  constructor(private db: Database) {}

  async head(principal: Principal, incidentId: string): Promise<AuditEvent | undefined> {
    return first<AuditEvent>(this.db, 'SELECT * FROM audit_events WHERE workspace_id = ? AND incident_id = ? ORDER BY sequence DESC LIMIT 1', [principal.workspaceId, incidentId])
  }

  append(principal: Principal, incidentId: string, sequence: number, action: string, payload: unknown, previousHash: string): Statement {
    const event = {
      id: newId(), workspace_id: principal.workspaceId, incident_id: incidentId,
      sequence, actor_id: principal.id, action, payload: canonical(payload),
      previous_hash: previousHash, created_at: now(),
    }
    return {
      sql: 'INSERT INTO audit_events (id, workspace_id, incident_id, sequence, actor_id, action, payload, previous_hash, hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      params: [event.id, event.workspace_id, event.incident_id, event.sequence, event.actor_id, event.action, event.payload, event.previous_hash, eventHash(event), event.created_at],
    }
  }

  list(principal: Principal, incidentId: string, after: number, limit: number) {
    return this.db.all<AuditEvent>('SELECT * FROM audit_events WHERE workspace_id = ? AND incident_id = ? AND sequence > ? ORDER BY sequence LIMIT ?', [principal.workspaceId, incidentId, after, limit])
  }

  async verify(principal: Principal, incidentId: string, revision: number) {
    let expectedSequence = 0, previous = GENESIS
    // Bound each read. The revision supplied by the caller defines the verification snapshot.
    while (expectedSequence <= revision) {
      const rows = await this.db.all<AuditEvent>('SELECT * FROM audit_events WHERE workspace_id = ? AND incident_id = ? AND sequence >= ? AND sequence <= ? ORDER BY sequence LIMIT 100', [principal.workspaceId, incidentId, expectedSequence, revision])
      if (!rows.length) return { valid: false, verifiedEvents: expectedSequence, brokenAt: expectedSequence, head: previous }
      for (const row of rows) {
        const { hash, ...content } = row
        if (row.sequence !== expectedSequence || row.previous_hash !== previous || eventHash(content) !== hash) {
          return { valid: false, verifiedEvents: expectedSequence, brokenAt: expectedSequence, head: previous }
        }
        previous = hash
        expectedSequence++
      }
    }
    return { valid: true, verifiedEvents: expectedSequence, brokenAt: null, head: previous }
  }
}
