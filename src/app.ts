import Fastify from 'fastify'
import swagger from '@fastify/swagger'
import swaggerUi from '@fastify/swagger-ui'
import { jsonSchemaTransform, serializerCompiler, validatorCompiler, hasZodFastifySchemaValidationErrors } from 'fastify-type-provider-zod'
import type { Config } from './core/config'
import { AppError, StorageError } from './core/errors'
import type { Database } from './db/database'
import { registerRoutes } from './modules/routes'

export async function createApp(config: Config, db: Database) {
  const app = Fastify({
    logger: config.LOG_LEVEL === 'silent' ? false : {
      level: config.LOG_LEVEL,
      redact: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]'],
    },
    bodyLimit: 65_536,
    requestTimeout: 30_000,
    connectionTimeout: 10_000,
    trustProxy: false,
    genReqId: () => crypto.randomUUID(),
  })
  app.decorateRequest('principal', null)
  app.setValidatorCompiler(validatorCompiler)
  app.setSerializerCompiler(serializerCompiler)

  app.setErrorHandler((error, request, reply) => {
    let status = 500, code = 'INTERNAL_ERROR', message = 'An unexpected error occurred'
    if (error instanceof AppError) { status = error.status; code = error.code; message = error.message }
    else if (error instanceof StorageError) {
      status = error.conflict ? 409 : 503
      code = error.conflict ? 'WRITE_CONFLICT' : 'STORAGE_UNAVAILABLE'
      message = error.conflict ? 'Write conflict; refetch the latest revision before retrying' : 'Storage is temporarily unavailable'
    } else if (hasZodFastifySchemaValidationErrors(error)) {
      status = 400; code = 'VALIDATION_ERROR'; message = 'Request does not match the documented schema'
    } else if (typeof error.statusCode === 'number' && error.statusCode >= 400 && error.statusCode < 500) {
      status = error.statusCode
      code = status === 429 ? 'RATE_LIMITED' : 'INVALID_REQUEST'
      message = status === 429 ? 'Too many requests; wait before retrying' : 'Invalid request'
    }
    if (status >= 500) request.log.error({ code, requestId: request.id }, 'Request failed')
    if (status === 401) reply.header('WWW-Authenticate', 'Bearer')
    return reply.code(status).send({ error: { code, message, requestId: request.id } })
  })
  app.setNotFoundHandler((request, reply) => reply.code(404).send({ error: { code: 'NOT_FOUND', message: 'Route not found', requestId: request.id } }))

  await app.register(swagger, {
    openapi: {
      info: { title: 'Aftermark API', version: '1.0.0', description: 'Evidence-driven incident response with independent approval gates. Send API keys as Bearer tokens. Mutations require the current expectedRevision.' },
      components: { securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', description: 'Workspace API key' },
        bootstrapAuth: { type: 'http', scheme: 'bearer', description: 'Operator-only bootstrap token; never distribute to clients' },
      } },
    },
    transform: jsonSchemaTransform,
  })
  await app.register(swaggerUi, { routePrefix: '/docs', uiConfig: { persistAuthorization: false } })

  app.get('/', { schema: { hide: true } }, async () => ({ name: 'Aftermark', version: '1.0.0', docs: '/docs', health: '/health/live' }))
  app.get('/health/live', { schema: { tags: ['Operations'], summary: 'Process liveness' } }, async () => ({ status: 'ok' }))
  app.get('/health/ready', { schema: { tags: ['Operations'], summary: 'Database and schema readiness' } }, async () => {
    await db.all('SELECT id FROM workspaces LIMIT 1')
    return { status: 'ready' }
  })
  app.get('/openapi.json', { schema: { hide: true } }, async () => app.swagger())
  await registerRoutes(app, db, config)
  return app
}
