module.exports = {
  apps: [{
    name: 'aftermark-smoke',
    cwd: '/home/user/webapp',
    script: './node_modules/.bin/bun',
    args: 'tests/http-smoke.ts',
    interpreter: 'none',
    autorestart: false,
    watch: false,
    instances: 1,
  }],
}
