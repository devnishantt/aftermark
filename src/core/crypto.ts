import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

export const sha256 = (text: string): string => createHash('sha256').update(text).digest('hex')

export function secretEqual(a: string, b: string): boolean {
  // Fixed-size digests avoid both length leaks and timingSafeEqual length exceptions.
  return timingSafeEqual(Buffer.from(sha256(a), 'hex'), Buffer.from(sha256(b), 'hex'))
}

export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`
}

export const keyDigest = (key: string, pepper: string): string => createHmac('sha256', pepper).update(key).digest('hex')
export const newApiKey = (): string => `am_live_${randomBytes(32).toString('base64url')}`
export const newId = (): string => crypto.randomUUID()
export const now = (): string => new Date().toISOString()
