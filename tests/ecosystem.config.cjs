const { resolve } = require('node:path')

module.exports = {
  apps: [{
    name: 'aftermark-smoke',
    cwd: resolve(__dirname, '..'),
    script: './node_modules/.bin/bun',
    args: 'tests/http-smoke.ts',
    interpreter: 'none',
    autorestart: false,
    watch: false,
    instances: 1,
  }],
}
