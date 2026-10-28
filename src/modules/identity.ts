import type { FastifyRequest } from 'fastify'
import type { z } from 'zod'
import type { Config } from '../core/config'
import { keyDigest, newApiKey, newId, now, secretEqual } from '../core/crypto'
import { assert } from '../core/errors'
import { first, type Database } from '../db/database'
import type { keyInput, Principal, workspaceInput } from './schemas'

declare module 'fastify' {
  interface FastifyRequest { principal: Principal | null }
}

type KeyRow = { id: string; workspace_id: string; role: Principal['role']; expires_at: string; revoked_at: string | null }

export class IdentityService {
  constructor(private db: Database, private config: Pick<Config, 'API_KEY_PEPPER' | 'BOOTSTRAP_TOKEN'>) {}

  async authenticate(request: FastifyRequest): Promise<void> {
    const token = request.headers.authorization?.match(/^Bearer (am_live_[A-Za-z0-9_-]{43})$/)?.[1]
    assert(token, 401, 'UNAUTHORIZED', 'A valid Bearer API key is required')
    const row = await first<KeyRow>(this.db, 'SELECT id, workspace_id, role, expires_at, revoked_at FROM api_keys WHERE digest = ?', [keyDigest(token, this.config.API_KEY_PEPPER)])
    assert(row && !row.revoked_at && row.expires_at > now(), 401, 'UNAUTHORIZED', 'API key is invalid, expired, or revoked')
    request.principal = { id: row.id, workspaceId: row.workspace_id, role: row.role }
  }

  bootstrap(authorization: string | undefined): void {
    const token = authorization?.match(/^Bearer (.+)$/)?.[1] ?? ''
    assert(secretEqual(token, this.config.BOOTSTRAP_TOKEN), 401, 'UNAUTHORIZED', 'Bootstrap authorization required')
  }

  require(request: FastifyRequest, roles: Principal['role'][]): Principal {
    assert(request.principal, 401, 'UNAUTHORIZED', 'Authentication required')
    assert(roles.includes(request.principal.role), 403, 'FORBIDDEN', 'This role cannot perform this operation')
    return request.principal
  }

  private issue(workspaceId: string, data: z.infer<typeof keyInput>) {
    const key = newApiKey(), id = newId(), created = now()
    const expires = new Date(Date.now() + data.expiresInDays * 86_400_000).toISOString()
    return {
      public: { id, key, role: data.role, label: data.label, expiresAt: expires },
      statement: {
        sql: 'INSERT INTO api_keys (id, workspace_id, label, role, digest, prefix, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        params: [id, workspaceId, data.label, data.role, keyDigest(key, this.config.API_KEY_PEPPER), key.slice(0, 16), created, expires],
      },
    }
  }

  async createWorkspace(data: z.infer<typeof workspaceInput>) {
    const id = newId(), createdAt = now()
    const issued = this.issue(id, { label: 'Initial administrator', role: 'admin', expiresInDays: 30 })
    await this.db.batch([
      { sql: 'INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)', params: [id, data.name, createdAt] },
      issued.statement,
    ])
    return { workspace: { id, name: data.name, createdAt }, apiKey: issued.public }
  }

  async createKey(principal: Principal, data: z.infer<typeof keyInput>) {
    const issued = this.issue(principal.workspaceId, data)
    await this.db.batch([issued.statement])
    return issued.public
  }

  listKeys(principal: Principal) {
    return this.db.all('SELECT id, label, role, prefix, created_at, expires_at, revoked_at FROM api_keys WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 200', [principal.workspaceId])
  }

  async revokeKey(principal: Principal, id: string) {
    assert(id !== principal.id, 409, 'SELF_REVOCATION', 'Use a different administrator key to revoke this credential')
    // Check and mutate in one statement, preserving at least one unexpired admin.
    const rows = await this.db.all<{ id: string }>(`
      UPDATE api_keys SET revoked_at = ? WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL
      AND (role != 'admin' OR EXISTS (
        SELECT 1 FROM api_keys AS other WHERE other.workspace_id = api_keys.workspace_id
        AND other.id != api_keys.id AND other.role = 'admin' AND other.revoked_at IS NULL AND other.expires_at > ?
      )) RETURNING id`, [now(), principal.workspaceId, id, now()])
    assert(rows.length, 409, 'KEY_NOT_REVOCABLE', 'Key not found, already revoked, or it is the last active administrator')
  }
}
