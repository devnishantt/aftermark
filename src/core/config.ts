import { z } from 'zod'

const settings = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['silent', 'error', 'warn', 'info', 'debug']).default('info'),
  BOOTSTRAP_TOKEN: z.string().min(32),
  API_KEY_PEPPER: z.string().min(32),
  CF_ACCOUNT_ID: z.string().regex(/^[a-f0-9]{32}$/),
  CF_D1_DATABASE_ID: z.uuid(),
  CF_D1_TOKEN: z.string().min(20),
  CORS_ORIGINS: z.string().default(''),
})

export type Config = z.infer<typeof settings>

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const result = settings.safeParse(env)
  if (!result.success) {
    // Report field names, never rejected values, because these fields contain credentials.
    throw new Error(`Invalid configuration: ${result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ')}`)
  }
  if (result.data.BOOTSTRAP_TOKEN === result.data.API_KEY_PEPPER) {
    throw new Error('BOOTSTRAP_TOKEN and API_KEY_PEPPER must be independent secrets')
  }
  return result.data
}
