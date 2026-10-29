import { describe, expect, test } from 'bun:test'
import { canonical, keyDigest, newApiKey, secretEqual, sha256 } from '../src/core/crypto'
import { loadConfig } from '../src/core/config'
import { StorageError } from '../src/core/errors'
import { D1Database } from '../src/db/d1'
import { testConfig, TestDatabase } from './helpers'

describe('cryptographic primitives', () => {
  test('canonicalizes nested keys without changing array order', () => {
    expect(canonical({ z: [2, 1], a: { c: 1, b: true } })).toBe('{"a":{"b":true,"c":1},"z":[2,1]}')
    expect(sha256(canonical({ b: 1, a: 2 }))).toBe(sha256(canonical({ a: 2, b: 1 })))
  })
  test('compares secrets without exposing variable-length values', () => {
    expect(secretEqual('secret', 'secret')).toBe(true)
    expect(secretEqual('secret', '')).toBe(false)
  })
  test('generates unique, high entropy keys and pepper-dependent digests', () => {
    const key = newApiKey()
    expect(key).toMatch(/^am_live_[A-Za-z0-9_-]{43}$/)
    expect(newApiKey()).not.toBe(key)
    expect(keyDigest(key, 'a')).not.toBe(keyDigest(key, 'b'))
  })
})

describe('configuration', () => {
  test('rejects invalid secrets without printing them', () => {
    const broken = { ...testConfig, PORT: '3000', BOOTSTRAP_TOKEN: 'do-not-leak' }
    expect(() => loadConfig(broken)).toThrow('BOOTSTRAP_TOKEN')
    try { loadConfig(broken) } catch (error) { expect(String(error)).not.toContain('do-not-leak') }
  })
  test('rejects shared bootstrap and pepper secrets', () => {
    expect(() => loadConfig({ ...testConfig, PORT: '3000', BOOTSTRAP_TOKEN: testConfig.API_KEY_PEPPER })).toThrow('independent secrets')
  })
})

describe('D1 REST adapter', () => {
  const transport = (handler: (input: unknown, init?: RequestInit) => Promise<Response>) => handler as typeof fetch
  const ok = (results: unknown[] = []) => Response.json({ success: true, result: [{ success: true, results }] })

  test('parameterizes reads and authenticates only at the server', async () => {
    const db = new D1Database(testConfig, transport(async (url, options) => {
      expect(String(url)).toContain('/query')
      expect(options?.headers).toEqual({ Authorization: `Bearer ${testConfig.CF_D1_TOKEN}`, 'Content-Type': 'application/json' })
      expect(JSON.parse(String(options?.body))).toEqual({ sql: 'SELECT ? AS value', params: ['safe'] })
      return ok([{ value: 'safe' }])
    }))
    expect(await db.all('SELECT ? AS value', ['safe'])).toEqual([{ value: 'safe' }])
  })
  test('sends a transaction as the documented batch object', async () => {
    const db = new D1Database(testConfig, transport(async (_url, options) => {
      expect(JSON.parse(String(options?.body))).toEqual({ batch: [{ sql: 'SELECT 1' }, { sql: 'SELECT 2', params: [] }] })
      return ok()
    }))
    await db.batch([{ sql: 'SELECT 1' }, { sql: 'SELECT 2', params: [] }])
  })
  test('maps uniqueness errors to write conflicts', async () => {
    const db = new D1Database(testConfig, transport(async () => Response.json({ success: false, errors: [{ message: 'UNIQUE constraint failed: private_table' }] })))
    try { await db.batch([{ sql: 'INSERT' }]); throw new Error('Expected failure') }
    catch (error) { expect(error).toBeInstanceOf(StorageError); expect((error as StorageError).conflict).toBe(true); expect(String(error)).not.toContain('private_table') }
  })
  test('does not retry ambiguous network failures', async () => {
    let calls = 0
    const db = new D1Database(testConfig, transport(async () => { calls++; throw new Error('private diagnostic') }))
    await expect(db.batch([{ sql: 'UPDATE' }])).rejects.toThrow('Storage unavailable')
    expect(calls).toBe(1)
  })
  test('rejects malformed and partially unsuccessful envelopes', async () => {
    for (const response of [Response.json({ unexpected: true }), Response.json({ success: true, result: [{ success: false, error: 'upstream failed' }] })]) {
      const db = new D1Database(testConfig, transport(async () => response))
      await expect(db.all('SELECT 1')).rejects.toBeInstanceOf(StorageError)
    }
  })
  test('does not send empty batches', async () => {
    const db = new D1Database(testConfig, transport(async () => { throw new Error('Must not call') }))
    await db.batch([])
  })
})

test('schema migration is repeatable and database foreign keys are enforced', async () => {
  const db = new TestDatabase()
  await db.initialize()
  await db.initialize()
  await expect(db.batch([{ sql: 'INSERT INTO api_keys (id, workspace_id, label, role, digest, prefix, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', params: ['id', 'missing-workspace', 'label', 'admin', 'digest', 'prefix', 'now', 'later'] }])).rejects.toBeInstanceOf(StorageError)
  db.raw.close()
})
