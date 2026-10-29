import { Database as SQLite } from 'bun:sqlite'
import type { HTTPMethods } from 'fastify'
import { createApp } from '../src/app'
import type { Config } from '../src/core/config'
import { StorageError } from '../src/core/errors'
import type { Database, Scalar, Statement } from '../src/db/database'

// In-memory SQLite is a TEST DOUBLE only. Production uses the D1 REST adapter.
export class TestDatabase implements Database {
  readonly raw = new SQLite(':memory:')
  failNextBatch = false

  async initialize() {
    this.raw.exec('PRAGMA foreign_keys = ON')
    this.raw.exec(await Bun.file(new URL('../migrations/001_initial.sql', import.meta.url)).text())
  }

  private normalize(error: unknown): never {
    throw new StorageError(error instanceof Error && /UNIQUE constraint|PRIMARY KEY/.test(error.message))
  }

  async all<T>(sql: string, params: Scalar[] = []): Promise<T[]> {
    try { return this.raw.query(sql).all(...params) as T[] }
    catch (error) { return this.normalize(error) }
  }

  async batch(statements: Statement[]) {
    try {
      this.raw.transaction(() => {
        for (const [index, statement] of statements.entries()) {
          if (statement.params?.length) this.raw.query(statement.sql).run(...statement.params)
          else this.raw.exec(statement.sql)
          if (this.failNextBatch && index === 0) {
            this.failNextBatch = false
            throw new Error('Injected transaction failure')
          }
        }
      })()
    } catch (error) { this.normalize(error) }
  }
}

export const testConfig: Config = {
  NODE_ENV: 'test', PORT: 3000, HOST: '0.0.0.0', LOG_LEVEL: 'silent',
  BOOTSTRAP_TOKEN: 'test-bootstrap-secret-not-for-production-0000',
  API_KEY_PEPPER: 'test-independent-pepper-not-for-production-1111',
  CF_ACCOUNT_ID: '0'.repeat(32), CF_D1_DATABASE_ID: '00000000-0000-4000-8000-000000000000',
  CF_D1_TOKEN: 'test-d1-token-not-for-production', CORS_ORIGINS: 'https://console.example.com',
}

export async function fixture() {
  const db = new TestDatabase()
  await db.initialize()
  const app = await createApp(testConfig, db)
  await app.ready()
  const request = (method: HTTPMethods, url: string, token?: string, payload?: object) => app.inject({
    method, url,
    ...(token ? { headers: { authorization: `Bearer ${token}` } } : {}),
    ...(payload ? { payload } : {}),
  })
  const workspace = async (name = 'Response laboratory') => {
    const response = await request('POST', '/v1/workspaces', testConfig.BOOTSTRAP_TOKEN, { name })
    if (response.statusCode !== 201) throw new Error(response.body)
    return response.json() as { workspace: { id: string }; apiKey: { id: string; key: string } }
  }
  const key = async (admin: string, role: 'admin' | 'responder' | 'observer' = 'responder') => {
    const response = await request('POST', '/v1/keys', admin, { label: `${role} credential`, role })
    if (response.statusCode !== 201) throw new Error(response.body)
    return response.json() as { id: string; key: string }
  }
  const incident = async (token: string) => {
    const response = await request('POST', '/v1/incidents', token, { title: 'Unexpected signing-key usage', summary: 'A signing key was observed outside its approved release window.', severity: 'critical' })
    if (response.statusCode !== 201) throw new Error(response.body)
    return response.json() as { id: string; revision: number; state: string }
  }
  return { app, db, request, workspace, key, incident, close: async () => { await app.close(); db.raw.close() } }
}
