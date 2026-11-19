#!/usr/bin/env node
/**
 * Mock TunnelGate API + static host for the built SPA in web/dist.
 *
 * The real FastAPI app is the source of truth; this exists so the panel can be
 * developed, screenshotted and reviewed before the API layer lands. It answers
 * the frozen contract from CONTRACT.md with in-memory data and serves the built
 * SPA the way app/main.py does (assets + catch-all index.html).
 *
 *   npm run build && npm run mock      # http://127.0.0.1:8080  admin / admin
 *
 * Nothing here is imported by the production bundle.
 */
import { createServer } from 'node:http'
import { readFile, stat } from 'node:fs/promises'
import { extname, join, normalize, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomUUID, createHash, createHmac } from 'node:crypto'

const HERE = resolve(fileURLToPath(new URL('.', import.meta.url)))
const DIST = resolve(HERE, '..', 'dist')
const PORT = Number(process.env.PORT ?? 8080)
const HOST = process.env.HOST ?? '127.0.0.1'

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.map': 'application/json; charset=utf-8',
}

/* --------------------------------------------------------------- fixtures */
const now = () => new Date().toISOString()
const ago = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString()

const users = [
  {
    id: 1,
    username: 'admin',
    display_name: 'Anna Kovalenko',
    role: 'admin',
    is_active: true,
    created_at: ago(60 * 24 * 90),
    last_login_at: ago(3),
  },
  {
    id: 2,
    username: 'operator',
    display_name: 'Marek Nowak',
    role: 'operator',
    is_active: true,
    created_at: ago(60 * 24 * 40),
    last_login_at: ago(120),
  },
  {
    id: 3,
    username: 'viewer',
    display_name: 'Sam Ortiz',
    role: 'viewer',
    is_active: true,
    created_at: ago(60 * 24 * 10),
    last_login_at: ago(60 * 26),
  },
  {
    id: 4,
    username: 'contractor',
    display_name: null,
    role: 'viewer',
    is_active: false,
    created_at: ago(60 * 24 * 200),
    last_login_at: null,
  },
]

function makeRouter(i, overrides) {
  const id = (overrides && overrides.id) || randomUUID()
  return Object.assign(
    {
      id: id,
      name: 'Site ' + String(i).padStart(2, '0'),
      slug: 'site-' + String(i).padStart(2, '0'),
      group_name: ['Kyiv', 'Lviv', 'Odesa', 'Remote'][i % 4],
      integrations: i % 3 === 0 ? ['singbox'] : i % 3 === 1 ? [] : ['singbox', 'adblock'],
      os_type: 'linux',
      notes: null,
      status: 'pending',
      online: false,
      http_port: 80,
      remote_port: 20000 + i,
      reverse_port: 22000 + i,
      console_port: 25000 + i,
      console_ready: false,
      bind_address: '127.0.0.1',
      url: null,
      hostname: null,
      model: null,
      openwrt_version: null,
      mac: null,
      client_ip: null,
      client_version: null,
      uptime_seconds: null,
      key_fingerprint: null,
      has_key: false,
      installed: false,
      tunnel_present: false,
      health_ok: null,
      created_at: ago(60 * 24 * 20 + i),
      updated_at: ago(60 + i),
      last_seen_at: null,
      last_heartbeat_at: null,
      online_since: null,
      bootstrap_expires_at: null,
    },
    overrides || {},
  )
}

const MODELS = ['Xiaomi AX3000T', 'GL.iNet MT3000', 'Netgear R7800', 'TP-Link Archer AX23', 'Banana Pi R3']
const VERSIONS = ['23.05.5', '24.10.0', 'SNAPSHOT r28412']

const routers = [
  makeRouter(1, {
    name: 'Kyiv office gateway',
    slug: 'kyiv-office',
    group_name: 'Kyiv',
    integrations: ['singbox'],
    status: 'online',
    online: true,
    url: 'https://kyiv-office.panel.example',
    hostname: 'kyiv-gw-01',
    model: MODELS[0],
    openwrt_version: VERSIONS[0],
    mac: 'a4:2b:8c:11:0d:01',
    client_ip: '10.8.0.11',
    client_version: '1.4.2',
    uptime_seconds: 12 * 86400 + 3611,
    key_fingerprint: 'SHA256:uK3mZ1pQ8xR2vT7yB4nL6cD9fH0jK5sW2aE8gM3qX1o',
    has_key: true,
    installed: true,
    tunnel_present: true,
    health_ok: true,
    console_ready: true,
    last_seen_at: ago(0.2),
    last_heartbeat_at: ago(0.2),
    online_since: ago(60 * 24 * 12),
  }),
  makeRouter(2, {
    name: 'Lviv warehouse',
    slug: 'lviv-warehouse',
    group_name: 'Lviv',
    integrations: [],
    status: 'online',
    online: true,
    url: 'https://lviv-warehouse.panel.example',
    hostname: 'lviv-wh-01',
    model: MODELS[1],
    openwrt_version: VERSIONS[1],
    mac: 'a4:2b:8c:11:0d:02',
    client_ip: '10.8.0.12',
    client_version: '1.4.2',
    uptime_seconds: 3 * 86400 + 120,
    key_fingerprint: 'SHA256:Bx9tR2vY5nM1cD8fH3jK6sW0aE7gM4qX2oP9uK3mZ5b',
    has_key: true,
    installed: true,
    tunnel_present: true,
    health_ok: true,
    console_ready: true,
    last_seen_at: ago(0.4),
    last_heartbeat_at: ago(0.4),
    online_since: ago(60 * 24 * 3),
  }),
  makeRouter(3, {
    name: 'Odesa branch',
    slug: 'odesa-branch',
    group_name: 'Odesa',
    integrations: ['singbox', 'adblock'],
    status: 'offline',
    online: false,
    url: 'https://odesa-branch.panel.example',
    hostname: 'odesa-br-01',
    model: MODELS[2],
    openwrt_version: VERSIONS[0],
    mac: 'a4:2b:8c:11:0d:03',
    client_ip: '10.8.0.13',
    client_version: '1.3.9',
    uptime_seconds: 0,
    key_fingerprint: 'SHA256:Cc1uS3wZ6oN2dE9gJ4kL7tX1bF8hN5rY3pQ0vL4nA6c',
    has_key: true,
    installed: true,
    tunnel_present: false,
    health_ok: false,
    console_ready: true,
    last_seen_at: ago(95),
    last_heartbeat_at: ago(95),
    online_since: null,
  }),
  makeRouter(4, {
    name: 'Remote lab router',
    slug: 'remote-lab',
    group_name: 'Remote',
    integrations: ['singbox'],
    status: 'awaiting',
    notes: 'Spare unit used for firmware testing before rollouts.',
    bootstrap_expires_at: new Date(Date.now() + 9 * 60_000).toISOString(),
  }),
  makeRouter(5, {
    name: 'Dnipro shop',
    slug: 'dnipro-shop',
    group_name: 'Kyiv',
    integrations: [],
    status: 'pending',
  }),
  makeRouter(6, {
    name: 'Kharkiv office',
    slug: 'kharkiv-office',
    group_name: 'Remote',
    integrations: ['singbox'],
    status: 'online',
    online: true,
    url: 'https://kharkiv-office.panel.example',
    hostname: 'kharkiv-of-01',
    model: MODELS[3],
    openwrt_version: VERSIONS[2],
    mac: 'a4:2b:8c:11:0d:06',
    client_ip: '10.8.0.16',
    client_version: '1.4.2',
    uptime_seconds: 86400 + 4000,
    key_fingerprint: 'SHA256:Dd2vT4xY7pO3eF0hK5lM8uW2cG9jP6sZ4rR1wM5oB7d',
    has_key: true,
    installed: true,
    tunnel_present: true,
    health_ok: true,
    console_ready: true,
    last_seen_at: ago(0.1),
    last_heartbeat_at: ago(0.1),
    online_since: ago(60 * 24),
  }),
]

const AUDIT_ACTIONS = [
  'auth.login',
  'auth.logout',
  'router.create',
  'router.update',
  'router.delete',
  'router.rotate_key',
  'console.open',
  'console.close',
  'user.create',
  'proxy.write_vhost',
  'health.check',
]

const audit = Array.from({ length: 84 }).map(function (_, i) {
  const action = AUDIT_ACTIONS[i % AUDIT_ACTIONS.length]
  const failed = action === 'health.check' && i % 7 === 0
  return {
    id: 5000 - i,
    ts: ago(i * 37 + 1),
    actor_username: i % 5 === 0 ? 'system' : i % 2 === 0 ? 'admin' : 'operator',
    action: action,
    outcome: failed ? 'failed' : action === 'router.delete' ? 'denied' : 'ok',
    router_id: routers[i % routers.length].id,
    router_name: routers[i % routers.length].name,
    ip: '10.8.' + (i % 4) + '.' + (20 + (i % 200)),
    detail: failed
      ? 'GET http://127.0.0.1:22102/ -> connection refused (111)'
      : action === 'router.delete'
        ? 'role viewer may not delete routers'
        : null,
  }
})

const consoleSessions = [
  {
    id: 'cs-1',
    router_id: routers[0].id,
    router_name: routers[0].name,
    username: 'admin',
    client_ip: '10.8.4.20',
    started_at: ago(38),
    closed_at: ago(31),
    close_reason: 'closed by user',
    bytes_in: 18432,
    bytes_out: 91204,
  },
  {
    id: 'cs-2',
    router_id: routers[0].id,
    router_name: routers[0].name,
    username: 'operator',
    client_ip: '10.8.4.31',
    started_at: ago(180),
    closed_at: ago(173),
    close_reason: 'idle timeout',
    bytes_in: 2048,
    bytes_out: 12889,
  },
]

const config = {
  panel_url: 'https://panel.example',
  subdomain_suffix: 'panel.example',
  bootstrap_ttl_minutes: 15,
  poll_interval_seconds: 3,
  proxy_driver: 'nginx',
  version: '0.1.0',
}

const sessions = new Map()
const pendingTickets = new Map()
const loginAttempts = new Map()

/* ---------------------------------------------------------------- helpers */
function json(res, status, body, headers) {
  const payload = body === undefined ? '' : JSON.stringify(body)
  res.writeHead(
    status,
    Object.assign(
      { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      headers || {},
    ),
  )
  res.end(payload)
}

function fail(res, status, code, message, details, headers) {
  const error = { code: code, message: message }
  if (details !== undefined) error.details = details
  json(res, status, { error: error }, headers)
}

function readBody(req) {
  return new Promise(function (res2, rej) {
    const chunks = []
    req.on('data', function (c) {
      chunks.push(c)
    })
    req.on('end', function () {
      const raw = Buffer.concat(chunks).toString('utf8')
      if (!raw) return res2({})
      try {
        res2(JSON.parse(raw))
      } catch (err) {
        rej(new Error('invalid json'))
      }
    })
    req.on('error', rej)
  })
}

function cookie(req, name) {
  const header = req.headers.cookie || ''
  const parts = header.split(';')
  for (const part of parts) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim()
  }
  return null
}

function currentSession(req) {
  const sid = cookie(req, 'tg_session')
  return sid ? sessions.get(sid) || null : null
}

function requireUser(req, res) {
  const session = currentSession(req)
  if (!session) {
    fail(res, 401, 'unauthenticated', 'Sign in to continue.')
    return null
  }
  return session
}

function requireCsrf(req, res, session) {
  if (req.method === 'GET' || req.method === 'HEAD') return true
  if (req.headers['x-csrf-token'] !== session.csrf) {
    fail(res, 403, 'csrf_failed', 'The CSRF token is missing or stale.')
    return false
  }
  return true
}

function publicRouter(r) {
  return Object.assign({}, r)
}

function routerListEnvelope(items) {
  return {
    items: items.map(publicRouter),
    total: items.length,
    online: items.filter((r) => r.status === 'online').length,
    offline: items.filter((r) => r.status === 'offline').length,
    pending: items.filter((r) => r.status === 'pending' || r.status === 'awaiting').length,
  }
}

function statsEnvelope() {
  return {
    routers_total: routers.length,
    routers_online: routers.filter((r) => r.status === 'online').length,
    routers_offline: routers.filter((r) => r.status === 'offline').length,
    routers_pending: routers.filter((r) => r.status === 'pending' || r.status === 'awaiting').length,
    ports_free: 412,
    users_total: users.length,
    console_sessions_active: consoleSessions.filter((s) => s.closed_at === null).length,
  }
}

/* The real command is built by app/services/bootstrap.py::build_install_command; this is a copy
   of its shape, kept so the SPA can be developed without a panel. Being a copy it can drift -
   the mock is a development fixture, never a source of truth. Two things about the shape are
   load-bearing and must survive any edit: the token rides as the basic-auth USERNAME (no stock
   OpenWrt has curl, and uclient-fetch had no --header before 24.10), and the body is fetched to a
   file and grepped for the installer's sentinel before it runs (a 401 answers an empty body, and
   piping that into sh is a silent success that leaves an operator staring at a dead router). */
function installCommand(router, token) {
  const url = config.panel_url + '/api/v1/routers/install?os=linux'
  return [
    'TK=' + token + '; U=' + url + '; F=/tmp/tg-install.$$.sh',
    "if command -v curl >/dev/null 2>&1; then curl -fsSL -o \"$F\" -u \"$TK:\" \"$U\"",
    "elif command -v wget >/dev/null 2>&1; then wget -q -O \"$F\" --user=\"$TK\" --password=x \"$U\"",
    "else echo 'TunnelGate: neither curl nor wget is installed on this router' >&2; exit 1; fi",
    "grep -q 'TunnelGate router agent installer' \"$F\" 2>/dev/null || { echo 'TunnelGate: the panel did not return the installer; mint a fresh install command and retry' >&2; rm -f \"$F\"; exit 1; }",
    'sh "$F"',
  ].join('\n')
}

function mintToken() {
  return 'tg_' + createHash('sha256').update(randomUUID()).digest('hex').slice(0, 40)
}

/* ------------------------------------------------------------------ routes */
async function handleApi(req, res, url) {
  const path = url.pathname
  const method = req.method || 'GET'

  /* ---- auth ---- */
  if (path === '/api/auth/login' && method === 'POST') {
    const body = await readBody(req)
    const attemptKey = String(body.username || '')
    const state = loginAttempts.get(attemptKey) || { failures: 0, blockedUntil: 0 }
    if (state.blockedUntil > Date.now()) {
      const seconds = Math.max(1, Math.ceil((state.blockedUntil - Date.now()) / 1000))
      fail(
        res,
        429,
        'rate_limited',
        'Too many attempts for this account. Wait ' + seconds + 's before trying again.',
        { retry_after: seconds },
        { 'retry-after': String(seconds) },
      )
      return
    }
    const user = users.find((u) => u.username === body.username)
    const allowed =
      user && (body.password === 'admin' || body.password === user.username) && user.is_active
    if (!allowed) {
      state.failures += 1
      if (state.failures >= 3) {
        state.failures = 0
        state.blockedUntil = Date.now() + 20000
      }
      loginAttempts.set(attemptKey, state)
      if (user && !user.is_active) {
        fail(res, 403, 'forbidden', 'That account is disabled.')
      } else {
        fail(res, 401, 'invalid_credentials', 'Wrong username or password.')
      }
      return
    }
    loginAttempts.delete(attemptKey)
    const sid = randomUUID()
    const csrf = randomUUID()
    user.last_login_at = now()
    sessions.set(sid, { user: user, csrf: csrf })
    json(
      res,
      200,
      { user: user, csrf_token: csrf, expires_at: new Date(Date.now() + 86400000).toISOString() },
      { 'set-cookie': 'tg_session=' + sid + '; Path=/; HttpOnly; SameSite=Lax' },
    )
    return
  }

  if (path === '/api/auth/me' && method === 'GET') {
    const session = currentSession(req)
    if (!session) {
      fail(res, 401, 'unauthenticated', 'No active session.')
      return
    }
    json(res, 200, {
      user: session.user,
      csrf_token: session.csrf,
      expires_at: new Date(Date.now() + 86400000).toISOString(),
    })
    return
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const session = currentSession(req)
    if (session) {
      const entries = Array.from(sessions.entries())
      for (const entry of entries) {
        if (entry[1] === session) sessions.delete(entry[0])
      }
    }
    res.writeHead(204, { 'set-cookie': 'tg_session=; Path=/; Max-Age=0; HttpOnly' })
    res.end()
    return
  }

  if (path === '/api/auth/password' && method === 'POST') {
    const session = requireUser(req, res)
    if (!session) return
    if (!requireCsrf(req, res, session)) return
    await readBody(req)
    res.writeHead(204)
    res.end()
    return
  }

  /* ---- meta ---- */
  if (path === '/api/v1/health' && method === 'GET') {
    json(res, 200, { status: 'ok' })
    return
  }

  const session = requireUser(req, res)
  if (!session) return
  if (!requireCsrf(req, res, session)) return

  if (path === '/api/v1/config' && method === 'GET') {
    json(res, 200, config)
    return
  }
  if (path === '/api/v1/stats' && method === 'GET') {
    json(res, 200, statsEnvelope())
    return
  }

  /* ---- routers ---- */
  if (path === '/api/v1/routers' && method === 'GET') {
    const status = url.searchParams.get('status')
    const q = (url.searchParams.get('q') || '').toLowerCase()
    let items = routers
    if (status && status !== 'all') items = items.filter((r) => r.status === status)
    if (q) {
      items = items.filter((r) =>
        [r.name, r.slug, r.group_name, r.hostname, r.client_ip, r.model]
          .filter(Boolean)
          .some((field) => String(field).toLowerCase().indexOf(q) !== -1),
      )
    }
    json(res, 200, routerListEnvelope(items))
    return
  }

  if (path === '/api/v1/routers' && method === 'POST') {
    const body = await readBody(req)
    const index = routers.length + 1
    const token = mintToken()
    const router = makeRouter(index, {
      name: body.name,
      slug: body.slug || 'site-' + index,
      group_name: body.group_name || null,
      integrations: body.integrations || [],
      os_type: body.os_type || 'linux',
      notes: body.notes || null,
      http_port: body.http_port || 80,
      status: 'awaiting',
      has_key: false,
      bootstrap_expires_at: new Date(Date.now() + config.bootstrap_ttl_minutes * 60000).toISOString(),
    })
    routers.unshift(router)
    json(
      res,
      201,
      Object.assign({}, publicRouter(router), {
        bootstrap_token: token,
        bootstrap_expires_at: router.bootstrap_expires_at,
        install_command: installCommand(router, token),
        install_script_url: config.panel_url + '/install',
      }),
    )
    return
  }

  const routerMatch = path.match(/^\/api\/v1\/routers\/([^/]+)(?:\/(rotate-key|status|script|console|console\/start))?$/)
  if (routerMatch) {
    const router = routers.find((r) => r.id === routerMatch[1])
    if (!router) {
      fail(res, 404, 'not_found', 'That router does not exist.')
      return
    }
    const sub = routerMatch[2]

    if (!sub && method === 'GET') {
      json(res, 200, publicRouter(router))
      return
    }
    if (!sub && method === 'PATCH') {
      const body = await readBody(req)
      const keys = ['name', 'group_name', 'notes', 'http_port']
      for (const key of keys) {
        if (key in body) router[key] = body[key]
      }
      router.updated_at = now()
      json(res, 200, publicRouter(router))
      return
    }
    if (!sub && method === 'DELETE') {
      routers.splice(routers.indexOf(router), 1)
      res.writeHead(204)
      res.end()
      return
    }
    if (sub === 'status' && method === 'GET') {
      let phase = 'waiting'
      if (router.status === 'online') phase = 'done'
      else if (router.status === 'offline') phase = 'offline'
      json(res, 200, {
        id: router.id,
        status: router.status,
        phase: phase,
        online: router.online,
        tunnel_present: router.tunnel_present,
        health_ok: router.health_ok,
        last_seen_at: router.last_seen_at,
        last_heartbeat_at: router.last_heartbeat_at,
        message: router.online ? 'tunnel up, heartbeat healthy' : 'waiting for the first heartbeat',
      })
      return
    }
    if (sub === 'script' && method === 'GET') {
      fail(
        res,
        404,
        'not_found',
        'The previous install command was not kept - rotate the key to mint a new one.',
      )
      return
    }
    if (sub === 'rotate-key' && method === 'POST') {
      const token = mintToken()
      router.has_key = false
      router.status = 'awaiting'
      router.bootstrap_expires_at = new Date(
        Date.now() + config.bootstrap_ttl_minutes * 60000,
      ).toISOString()
      json(res, 200, {
        bootstrap_token: token,
        bootstrap_expires_at: router.bootstrap_expires_at,
        install_command: installCommand(router, token),
        install_script_url: config.panel_url + '/install',
        note: 'The previous key was revoked and the install command stopped working.',
      })
      return
    }
    if (sub === 'console' && method === 'GET') {
      let state = 'offline'
      if (router.online) state = router.console_ready ? 'ready' : 'no_key'
      json(res, 200, {
        state: state,
        console_port: router.console_port,
        installed_at: router.console_ready ? ago(60 * 24 * 4) : null,
        fingerprint: router.console_ready ? 'SHA256:console-' + router.slug : null,
        active_sessions: consoleSessions.filter(
          (s) => s.router_id === router.id && s.closed_at === null,
        ).length,
        idle_timeout_seconds: 300,
        max_session_seconds: 3600,
      })
      return
    }
    if (sub === 'console/start' && method === 'POST') {
      if (!router.online) {
        fail(res, 503, 'console_offline', 'The router is offline, so no shell can be opened.')
        return
      }
      if (router.console_ready !== true) {
        fail(res, 409, 'console_not_ready', 'No console key has been registered on this router yet.')
        return
      }
      const ticket = randomUUID()
      pendingTickets.set(ticket, router.id)
      json(res, 200, {
        router_id: router.id,
        ticket: ticket,
        ws_path: '/api/v1/routers/' + router.id + '/console/ws?ticket=' + ticket,
        expires_at: new Date(Date.now() + 60000).toISOString(),
        console_port: router.console_port,
      })
      return
    }
  }

  if (path === '/api/v1/console/sessions' && method === 'GET') {
    json(res, 200, { items: consoleSessions, total: consoleSessions.length })
    return
  }

  /* ---- audit ---- */
  if (path === '/api/v1/audit' && method === 'GET') {
    const routerId = url.searchParams.get('router_id')
    const actor = url.searchParams.get('actor')
    const action = url.searchParams.get('action')
    const limit = Number(url.searchParams.get('limit') || 50)
    const offset = Number(url.searchParams.get('offset') || 0)
    let items = audit
    if (routerId) items = items.filter((a) => a.router_id === routerId)
    if (actor) items = items.filter((a) => (a.actor_username || '').indexOf(actor) !== -1)
    if (action) items = items.filter((a) => a.action.indexOf(action) !== -1)
    json(res, 200, { items: items.slice(offset, offset + limit), total: items.length })
    return
  }

  /* ---- users ---- */
  if (path === '/api/v1/users' && method === 'GET') {
    if (session.user.role !== 'admin') {
      fail(res, 403, 'forbidden', 'Only administrators can list users.')
      return
    }
    json(res, 200, { items: users, total: users.length })
    return
  }
  if (path === '/api/v1/users' && method === 'POST') {
    const body = await readBody(req)
    const user = {
      id: users.length + 1,
      username: body.username,
      display_name: body.display_name || null,
      role: body.role || 'viewer',
      is_active: true,
      created_at: now(),
      last_login_at: null,
    }
    users.push(user)
    json(res, 201, user)
    return
  }

  const userMatch = path.match(/^\/api\/v1\/users\/(\d+)$/)
  if (userMatch) {
    const id = Number(userMatch[1])
    const user = users.find((u) => u.id === id)
    if (!user) {
      fail(res, 404, 'not_found', 'That user does not exist.')
      return
    }
    if (method === 'PATCH') {
      const body = await readBody(req)
      if ('display_name' in body) user.display_name = body.display_name
      if ('role' in body) user.role = body.role
      if ('is_active' in body) user.is_active = body.is_active
      json(res, 200, user)
      return
    }
    if (method === 'DELETE') {
      users.splice(users.indexOf(user), 1)
      res.writeHead(204)
      res.end()
      return
    }
  }

  fail(res, 404, 'not_found', 'No such endpoint: ' + method + ' ' + path)
}


/* ------------------------------------------------------------------- ws */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

function wsAccept(key) {
  return createHash('sha1').update(key + WS_GUID).digest('base64')
}

function wsFrame(payload, opcode) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8')
  const code = opcode === undefined ? 0x1 : opcode
  let head
  if (body.length < 126) {
    head = Buffer.from([0x80 | code, body.length])
  } else if (body.length < 65536) {
    head = Buffer.alloc(4)
    head[0] = 0x80 | code
    head[1] = 126
    head.writeUInt16BE(body.length, 2)
  } else {
    head = Buffer.alloc(10)
    head[0] = 0x80 | code
    head[1] = 127
    head.writeBigUInt64BE(BigInt(body.length), 2)
  }
  return Buffer.concat([head, body])
}

function decodeFrames(buffer, onFrame) {
  let offset = 0
  while (offset + 2 <= buffer.length) {
    const b0 = buffer[offset]
    const b1 = buffer[offset + 1]
    const fin = (b0 & 0x80) !== 0
    const opcode = b0 & 0x0f
    const masked = (b1 & 0x80) !== 0
    let length = b1 & 0x7f
    let cursor = offset + 2
    if (length === 126) {
      if (cursor + 2 > buffer.length) return offset
      length = buffer.readUInt16BE(cursor)
      cursor += 2
    } else if (length === 127) {
      if (cursor + 8 > buffer.length) return offset
      length = Number(buffer.readBigUInt64BE(cursor))
      cursor += 8
    }
    let mask = null
    if (masked) {
      if (cursor + 4 > buffer.length) return offset
      mask = buffer.subarray(cursor, cursor + 4)
      cursor += 4
    }
    if (cursor + length > buffer.length) return offset
    const payload = Buffer.from(buffer.subarray(cursor, cursor + length))
    if (mask) {
      for (let i = 0; i < payload.length; i++) payload[i] = payload[i] ^ mask[i & 3]
    }
    onFrame(opcode, payload, fin)
    offset = cursor + length
  }
  return offset
}

function handleUpgrade(req, socket, head) {
  const url = new URL(req.url || '/', 'http://' + (req.headers.host || '127.0.0.1'))
  const match = url.pathname.match(/^\/api\/v1\/routers\/([^/]+)\/console\/ws$/)
  const session = currentSession(req)
  if (!match || !session) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n')
    socket.destroy()
    return
  }
  const ticket = url.searchParams.get('ticket')
  if (!ticket || pendingTickets.get(ticket) !== match[1]) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n')
    socket.destroy()
    return
  }
  pendingTickets.delete(ticket)

  const router = routers.find((r) => r.id === match[1])
  const key = req.headers['sec-websocket-key']
  if (!key) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n')
    socket.destroy()
    return
  }
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n',
  )

  const opened = { id: 'cs-' + randomUUID().slice(0, 8), router_id: match[1], router_name: router ? router.name : 'Router', username: session.user.username, client_ip: '127.0.0.1', started_at: now(), closed_at: null, close_reason: null, bytes_in: 0, bytes_out: 0 }
  consoleSessions.unshift(opened)

  function send(text) {
    socket.write(wsFrame(text, 0x1))
  }

  send(JSON.stringify({ type: 'status', message: 'connected to mock shell' }))
  send(
    '\r\nBusyBox v1.36.1 (mock shell)\r\n' +
      'TunnelGate mock console - keystrokes are echoed, nothing runs.\r\n\r\n' +
      'root@' + (router ? router.slug : 'router') + ':~# ',
  )

  let line = ''
  socket.on('data', function (chunk) {
    const rest = Buffer.from(chunk)
    decodeFrames(rest, function (opcode, payload) {
      if (opcode === 0x8) {
        socket.end(wsFrame(Buffer.alloc(0), 0x8))
        return
      }
      if (opcode === 0x9) {
        socket.write(wsFrame(payload, 0xa))
        return
      }
      const text = payload.toString('utf8')
      if (text.charAt(0) === '{') {
        return
      }
      opened.bytes_in += payload.length
      opened.bytes_out += payload.length
      for (const ch of text) {
        if (ch === '\r') {
          const out = '\r\nmock: ' + (line.trim() || 'nothing') + ' is not really executed\r\nroot@' + (router ? router.slug : 'router') + ':~# '
          send(out)
          line = ''
        } else if (ch === '\u007f') {
          if (line.length > 0) {
            line = line.slice(0, -1)
            send('\b \b')
          }
        } else {
          line += ch
          send(ch)
        }
      }
    })
  })

  socket.on('close', function () {
    opened.closed_at = now()
    opened.close_reason = 'closed by user'
  })
  socket.on('error', function () {})
}

/* ------------------------------------------------------------ static host */
async function serveStatic(req, res, url) {
  let pathname
  try {
    pathname = decodeURIComponent(url.pathname)
  } catch (err) {
    pathname = url.pathname
  }
  if (pathname === '/') pathname = '/index.html'

  const candidate = resolve(join(DIST, normalize(pathname).replace(/^(\.\.[\/\\])+/, '')))
  if (candidate.indexOf(DIST) === 0) {
    try {
      const info = await stat(candidate)
      if (info.isFile()) {
        const body = await readFile(candidate)
        const ext = extname(candidate)
        res.writeHead(200, {
          'content-type': MIME[ext] || 'application/octet-stream',
          'cache-control': ext === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable',
        })
        res.end(body)
        return
      }
    } catch (err) {
      /* fall through to the SPA entry */
    }
  }

  try {
    const html = await readFile(join(DIST, 'index.html'))
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' })
    res.end(html)
  } catch (err) {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('web/dist is missing - run npm run build first.\n')
  }
}

/* ------------------------------------------------------------------ server */
const server = createServer(function (req, res) {
  const host = req.headers.host || HOST + ':' + PORT
  const url = new URL(req.url || '/', 'http://' + host)
  res.setHeader('x-content-type-options', 'nosniff')
  res.setHeader('referrer-policy', 'same-origin')

  if (url.pathname.indexOf('/api/') === 0) {
    handleApi(req, res, url).catch(function (err) {
      console.error(err)
      if (!res.headersSent) fail(res, 500, 'internal_error', 'The mock server crashed: ' + String(err))
      else res.end()
    })
    return
  }
  serveStatic(req, res, url).catch(function () {
    res.writeHead(500)
    res.end('static failure')
  })
})

server.on('upgrade', function (req, socket, head) {
  try {
    handleUpgrade(req, socket, head)
  } catch (err) {
    console.error(err)
    socket.destroy()
  }
})

server.listen(PORT, HOST, function () {
  console.log('TunnelGate mock panel on http://' + HOST + ':' + PORT + '   (admin / admin)')
  console.log('serving ' + DIST)
})