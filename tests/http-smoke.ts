import { fixture } from './helpers'

// Ephemeral loopback-only HTTP smoke service, never a production storage mode.
const f = await fixture()
await f.app.listen({ host: '127.0.0.1', port: 3000 })
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.once(signal, () => { void f.close().then(() => process.exit(0)) })
}
