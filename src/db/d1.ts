import { z } from 'zod'
import type { Config } from '../core/config'
import { StorageError } from '../core/errors'
import type { Database, Scalar, Statement } from './database'

const envelope = z.object({
  success: z.boolean(),
  errors: z.array(z.object({ message: z.string() })).optional(),
  result: z.array(z.object({
    success: z.boolean(),
    results: z.array(z.unknown()).optional(),
    error: z.string().optional(),
  })).optional(),
})

export class D1Database implements Database {
  private readonly url: string
  constructor(private config: Pick<Config, 'CF_ACCOUNT_ID' | 'CF_D1_DATABASE_ID' | 'CF_D1_TOKEN'>, private transport: typeof fetch = fetch) {
    this.url = `https://api.cloudflare.com/client/v4/accounts/${config.CF_ACCOUNT_ID}/d1/database/${config.CF_D1_DATABASE_ID}/query`
  }

  private async execute(body: Statement | { batch: Statement[] }): Promise<z.infer<typeof envelope>> {
    try {
      // Never retry mutations automatically: a timed-out write may already have committed.
      const response = await this.transport(this.url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${this.config.CF_D1_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      })
      const result = envelope.parse(await response.json())
      if (!response.ok || !result.success || !result.result?.length || result.result.some(r => !r.success)) {
        const detail = [...(result.errors ?? []).map(e => e.message), ...(result.result ?? []).map(r => r.error ?? '')].join(' ')
        // Do not return SQL, parameters, or upstream diagnostics to API callers.
        throw new StorageError(/UNIQUE constraint|PRIMARY KEY|constraint failed/i.test(detail))
      }
      return result
    } catch (error) {
      if (error instanceof StorageError) throw error
      throw new StorageError(false)
    }
  }

  async all<T>(sql: string, params: Scalar[] = []): Promise<T[]> {
    const response = await this.execute({ sql, params })
    return (response.result?.[0]?.results ?? []) as T[]
  }

  async batch(statements: Statement[]): Promise<void> {
    if (!statements.length) return
    // The REST API batch form uses the same transaction boundary as D1 batch().
    await this.execute({ batch: statements })
  }
}
