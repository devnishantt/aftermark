import type { FastifyInstance } from 'fastify'
import helmet from '@fastify/helmet'
import cors from '@fastify/cors'
import rateLimit from '@fastify/rate-limit'
import type { Config } from './config'

export async function harden(app: FastifyInstance, config: Config) {
  await app.register(helmet)
  const origins = config.CORS_ORIGINS.split(',').map(origin => origin.trim()).filter(Boolean)
  await app.register(cors, { origin: origins.length ? origins : false, credentials: false, methods: ['GET', 'POST', 'DELETE'] })
  await app.register(rateLimit, {
    global: true, max: 120, timeWindow: '1 minute',
    // This is process-local abuse protection, not a distributed quota.
    // A reverse proxy should enforce a fleet-wide budget in production.
    keyGenerator: request => request.ip,
    allowList: request => request.url === '/health/live',
  })
  app.addHook('onSend', async (request, reply, payload) => {
    reply.header('X-Request-Id', request.id)
    if (request.url.startsWith('/v1/')) reply.header('Cache-Control', 'no-store')
    return payload
  })
}
