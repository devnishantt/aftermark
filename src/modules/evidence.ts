import type { z } from 'zod'
import { canonical, newId, now, sha256 } from '../core/crypto'
import { assert } from '../core/errors'
import { IncidentService } from './incidents'
import { evidenceInput, type Evidence, type Incident, type Principal } from './schemas'

export class EvidenceService {
  constructor(private incidents: IncidentService) {}

  async list(principal: Principal, incidentId: string): Promise<Evidence[]> {
    await this.incidents.get(principal, incidentId)
    return this.incidents.db.all<Evidence>('SELECT * FROM evidence WHERE workspace_id = ? AND incident_id = ? ORDER BY id', [principal.workspaceId, incidentId])
  }

  async manifest(principal: Principal, incident: Incident) {
    const items = await this.list(principal, incident.id)
    // State/revision are deliberately excluded: workflow events do not alter evidence.
    // URI, label, uploader, and digest are all covered, not just artifact checksums.
    const manifest = {
      version: 1,
      incident: { id: incident.id, workspaceId: incident.workspace_id, title: incident.title, summary: incident.summary, severity: incident.severity },
      evidence: items,
    }
    return { manifest, manifestHash: sha256(canonical(manifest)), evidenceCount: items.length }
  }

  async add(principal: Principal, incidentId: string, input: z.infer<typeof evidenceInput>) {
    const incident = await this.incidents.checkRevision(principal, incidentId, input.expectedRevision)
    const existing = await this.list(principal, incidentId)
    assert(existing.length < 1000, 409, 'EVIDENCE_LIMIT', 'An incident may contain at most 1000 evidence references')
    assert(!existing.some(item => item.sha256 === input.sha256), 409, 'DUPLICATE_EVIDENCE', 'This artifact digest is already attached')
    const id = newId(), created = now()
    await this.incidents.mutate(principal, incident, 'evidence.attached', {
      id, label: input.label, uri: input.uri, sha256: input.sha256, mediaType: input.mediaType,
    }, [{
      sql: 'INSERT INTO evidence (id, workspace_id, incident_id, label, uri, sha256, media_type, added_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      params: [id, principal.workspaceId, incidentId, input.label, input.uri, input.sha256, input.mediaType, principal.id, created],
    }])
    return { id, incidentId, revision: incident.revision + 1 }
  }
}
