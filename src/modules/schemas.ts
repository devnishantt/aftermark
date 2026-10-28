import { z } from 'zod'

export const role = z.enum(['admin', 'responder', 'observer'])
export const state = z.enum(['open', 'investigating', 'contained', 'resolved'])
export const severity = z.enum(['low', 'medium', 'high', 'critical'])
const label = z.string().trim().min(1).max(120)
export const incidentParams = z.object({ id: z.uuid() })
export const keyParams = z.object({ id: z.uuid() })
export const workspaceInput = z.strictObject({ name: label })
export const keyInput = z.strictObject({
  label,
  role,
  expiresInDays: z.number().int().min(1).max(365).default(30),
})
export const incidentInput = z.strictObject({
  title: z.string().trim().min(3).max(200),
  summary: z.string().trim().min(10).max(5000),
  severity,
})
export const transitionInput = z.strictObject({
  expectedRevision: z.number().int().nonnegative(),
  state,
  reason: z.string().trim().min(10).max(2000),
})
export const evidenceInput = z.strictObject({
  expectedRevision: z.number().int().nonnegative(),
  label,
  uri: z.url().max(2000).refine(value => new URL(value).protocol === 'https:', 'Evidence URI must use HTTPS'),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  mediaType: z.string().regex(/^[\w.+-]+\/[\w.+-]+$/).max(120),
})
export const approvalInput = z.strictObject({
  expectedRevision: z.number().int().nonnegative(),
  manifestHash: z.string().regex(/^[a-f0-9]{64}$/),
  note: z.string().trim().min(10).max(2000),
})
export const incidentQuery = z.strictObject({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: z.string().max(500).optional(),
  state: state.optional(),
  severity: severity.optional(),
})
export const eventQuery = z.strictObject({
  after: z.coerce.number().int().min(-1).default(-1),
  limit: z.coerce.number().int().min(1).max(100).default(50),
})

export type Principal = { id: string; workspaceId: string; role: z.infer<typeof role> }
export type Incident = {
  id: string; workspace_id: string; title: string; summary: string;
  severity: z.infer<typeof severity>; state: z.infer<typeof state>;
  created_by: string; revision: number; created_at: string; updated_at: string;
}
export type Evidence = {
  id: string; workspace_id: string; incident_id: string; label: string; uri: string;
  sha256: string; media_type: string; added_by: string; created_at: string;
}
export type Approval = {
  id: string; workspace_id: string; incident_id: string; actor_id: string;
  manifest_hash: string; note: string; created_at: string;
}
export type AuditEvent = {
  id: string; workspace_id: string; incident_id: string; sequence: number;
  actor_id: string; action: string; payload: string; previous_hash: string;
  hash: string; created_at: string;
}
