import { readdir, readFile } from 'node:fs/promises'
import { loadConfig } from '../src/core/config'
import { sha256 } from '../src/core/crypto'
import { D1Database } from '../src/db/d1'

const db = new D1Database(loadConfig())
await db.batch([{ sql: 'CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)' }])
const directory = new URL('../migrations/', import.meta.url)
for (const name of (await readdir(directory)).filter(n => /^\d+.*\.sql$/.test(n)).sort()) {
  const sql = await readFile(new URL(name, directory), 'utf8')
  const checksum = sha256(sql)
  const [existing] = await db.all<{ checksum: string }>('SELECT checksum FROM schema_migrations WHERE name = ?', [name])
  if (existing) {
    if (existing.checksum !== checksum) throw new Error(`Applied migration changed: ${name}`)
    continue
  }
  await db.batch([
    { sql },
    { sql: 'INSERT INTO schema_migrations (name, checksum, applied_at) VALUES (?, ?, ?)', params: [name, checksum, new Date().toISOString()] },
  ])
  console.log(`Applied ${name}`)
}
