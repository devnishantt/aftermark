import { createApp } from './app'
import { loadConfig } from './core/config'
import { D1Database } from './db/d1'

const config = loadConfig()
const app = await createApp(config, new D1Database(config))

let shuttingDown = false
async function shutdown(signal: string) {
  if (shuttingDown) return
  shuttingDown = true
  app.log.info({ signal }, 'Draining connections')
  const deadline = setTimeout(() => process.exit(1), 15_000)
  deadline.unref()
  try {
    await app.close()
    clearTimeout(deadline)
    process.exitCode = 0
  } catch {
    process.exitCode = 1
  }
}
process.once('SIGINT', () => { void shutdown('SIGINT') })
process.once('SIGTERM', () => { void shutdown('SIGTERM') })

try {
  await app.listen({ host: config.HOST, port: config.PORT })
} catch {
  app.log.error('Startup failed; check bind address and port availability')
  process.exitCode = 1
}
