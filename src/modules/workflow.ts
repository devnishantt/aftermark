import type { z } from 'zod'
import { newId, now } from '../core/crypto'
import { assert } from '../core/errors'
import { EvidenceService } from './evidence'
import { IncidentService } from './incidents'
import { approvalInput, transitionInput, type Approval, type Incident, type Principal } from './schemas'

const transitions: Record<Incident['state'], Incident['state'][]> = {
  open: ['investigating'], investigating: ['contained'], contained: ['resolved'], resolved: [],
}

export class WorkflowService {
  constructor(private incidents: IncidentService, private evidence: EvidenceService) {}

  async approvals(principal: Principal, incidentId: string) {
    await this.incidents.get(principal, incidentId)
    return this.incidents.db.all<Approval>('SELECT * FROM approvals WHERE workspace_id = ? AND incident_id = ? ORDER BY created_at, id', [principal.workspaceId, incidentId])
  }

  async gate(principal: Principal, incident: Incident) {
    const { manifestHash, evidenceCount } = await this.evidence.manifest(principal, incident)
    const approvals = await this.approvals(principal, incident.id)
    const matching = approvals.filter(a => a.manifest_hash === manifestHash && a.actor_id !== incident.created_by)
    const approverCount = new Set(matching.map(a => a.actor_id)).size
    return {
      manifestHash, evidenceCount, approverCount, requiredApprovals: 2,
      staleApprovalCount: approvals.filter(a => a.manifest_hash !== manifestHash).length,
      canResolve: incident.state === 'contained' && evidenceCount > 0 && approverCount >= 2,
      allowedTransitions: transitions[incident.state],
    }
  }

  async approve(principal: Principal, incidentId: string, input: z.infer<typeof approvalInput>) {
    const incident = await this.incidents.checkRevision(principal, incidentId, input.expectedRevision)
    assert(incident.state === 'contained', 409, 'NOT_CONTAINED', 'Only contained incidents may be approved')
    assert(principal.id !== incident.created_by, 403, 'INDEPENDENCE_REQUIRED', 'The incident creator cannot approve their own incident')
    const manifest = await this.evidence.manifest(principal, incident)
    assert(manifest.evidenceCount > 0, 409, 'EVIDENCE_REQUIRED', 'Attach evidence before approval')
    assert(input.manifestHash === manifest.manifestHash, 409, 'MANIFEST_CHANGED', 'Review the latest manifest before approving')
    const id = newId()
    await this.incidents.mutate(principal, incident, 'incident.approved', { id, manifestHash: input.manifestHash, note: input.note }, [{
      sql: 'INSERT INTO approvals (id, workspace_id, incident_id, actor_id, manifest_hash, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      params: [id, principal.workspaceId, incidentId, principal.id, input.manifestHash, input.note, now()],
    }])
    return { id, revision: incident.revision + 1, manifestHash: input.manifestHash }
  }

  async transition(principal: Principal, incidentId: string, input: z.infer<typeof transitionInput>) {
    const incident = await this.incidents.checkRevision(principal, incidentId, input.expectedRevision)
    assert(transitions[incident.state].includes(input.state), 409, 'INVALID_TRANSITION', `Cannot transition from ${incident.state} to ${input.state}`)
    if (input.state === 'contained' || input.state === 'resolved') {
      const gate = await this.gate(principal, incident)
      assert(gate.evidenceCount > 0, 409, 'EVIDENCE_REQUIRED', 'Containment requires at least one evidence reference')
      if (input.state === 'resolved') assert(gate.canResolve, 409, 'APPROVALS_REQUIRED', 'Two independent principals must approve the current evidence manifest')
    }
    return this.incidents.mutate(principal, incident, 'incident.transitioned', { from: incident.state, to: input.state, reason: input.reason }, [{
      sql: 'UPDATE incidents SET state = ? WHERE workspace_id = ? AND id = ?', params: [input.state, principal.workspaceId, incidentId],
    }])
  }
}
