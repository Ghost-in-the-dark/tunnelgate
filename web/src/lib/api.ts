/**
 * The single HTTP entry point.
 *
 * Rules this file enforces so no screen has to think about them:
 *  - `credentials: 'include'` on every request (the session cookie is HttpOnly).
 *  - the CSRF token comes from the `tg_csrf` cookie, which the server sets beside the
 *    session cookie at login and deletes at logout. It is read here, per request, and
 *    only echoed back in the X-CSRF-Token header; nothing caches it in memory, in
 *    localStorage or anywhere else, so a token that rotates on the next login cannot be
 *    left behind by a tab that stayed open.
 *    It used to arrive in the JSON body of login and GET /api/auth/me. That was the bug:
 *    in the merged path layout a router page is same-origin with the panel, so a
 *    compromised router page could fetch /api/auth/me with the operator's cookie, read
 *    the token out of the response and mutate anything the operator could - a router page
 *    really did create a second admin account. A cookie is not fetchable as a body, so
 *    that step is gone; see docs/SECURITY.md for what it does and does not buy.
 *  - the API error envelope {`{"error":{code,message,details}}`} becomes a typed ApiError.
 *  - a 401 anywhere flips the auth store to "logged out", which unmounts the shell.
 */
import type {
  AgentEndpointInput,
  AgentEndpointResult,
  AgentEndpointTest,
  AuditListResponse,
  ConsoleInfo,
  ConsoleSessionList,
  ConsoleStart,
  CreateRouterInput,
  CreateUserInput,
  InstallScript,
  PanelConfig,
  Role,
  Router,
  RouterCreated,
  RouterListResponse,
  RouterStatus,
  Session,
  Stats,
  UpdateUserInput,
  User,
  UserRouterGrantList,
} from './types'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: unknown
  readonly retryAfter: number | null

  constructor(
    status: number,
    code: string,
    message: string,
    details: unknown = undefined,
    retryAfter: number | null = null,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
    this.retryAfter = retryAfter
  }

  /** Human text for a failure, preferring the server's message. */
  get human(): string {
    return friendlyMessage(this)
  }
}

/** 429 with no Retry-After still needs a sane countdown. */
export const DEFAULT_RETRY_AFTER = 30

const CSRF_HEADER = 'X-CSRF-Token'
// The cookie the server writes in the same response as the session cookie. Its value is the
// session's CSRF token; the server never puts that token in a response body, which is the
// whole point of the change. Read fresh on every mutating request, never cached: the browser
// is the storage, and the browser drops this cookie on logout.
//
// The name is the server default (TUNNELGATE_CSRF_COOKIE_NAME). It is a literal here because a
// static bundle cannot read the server's settings, and GET /api/v1/config is authenticated, so
// it is not available on the login screen where the first mutation happens. A deployment that
// renames the setting must rebuild this bundle with the new name - renaming it on the server
// alone leaves the panel able to log in but unable to mutate anything.
const CSRF_COOKIE = 'tg_csrf'

function readCsrfCookie(): string | null {
  // document.cookie is a string of `name=value; name=value`. The value is url-encoded on the
  // way in (the server uses set_cookie, which encodes it), so decode it before sending it
  // back in the header: the server compares the header against the raw session token.
  for (const part of document.cookie.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() !== CSRF_COOKIE) continue
    try {
      return decodeURIComponent(part.slice(eq + 1).trim())
    } catch {
      // A malformed cookie is not a token; let the request go out bare and take the 403.
      return null
    }
  }
  return null
}

// ------------------------------------------------------------------ auth store
interface AuthState {
  user: User | null
  /** 'unknown' until GET /api/auth/me answers; the router shows a splash meanwhile. */
  bootState: 'unknown' | 'authenticated' | 'anonymous'
}

let authState: AuthState = { user: null, bootState: 'unknown' }
const authListeners = new Set<(s: AuthState) => void>()

function emitAuth(next: AuthState) {
  authState = next
  for (const fn of authListeners) fn(authState)
}

export function getAuthState(): AuthState {
  return authState
}

export function subscribeAuth(fn: (s: AuthState) => void): () => void {
  authListeners.add(fn)
  return () => {
    authListeners.delete(fn)
  }
}

/** Called by the login screen after POST /api/auth/login succeeds. */
export function setSession(session: Session) {
  // The CSRF token is not in the answer any more: the login response set it as a cookie.
  // Nothing to store here, which is the point - a token this module does not hold cannot be
  // handed to a same-origin reader by a bug in this module.
  emitAuth({ user: session.user, bootState: 'authenticated' })
}

export function setUser(user: User) {
  emitAuth({ ...authState, user })
}

export function clearSession() {
  emitAuth({ user: null, bootState: 'anonymous' })
}

// ------------------------------------------------------------------ transport
interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'
  body?: unknown
  signal?: AbortSignal
  query?: Record<string, string | number | boolean | null | undefined>
  /** Set for the few calls that must not bounce the app to /login on 401. */
  allow401?: boolean
}

function buildUrl(path: string, query?: RequestOptions['query']): string {
  if (!query) return path
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue
    params.set(k, String(v))
  }
  const qs = params.toString()
  return qs ? `${path}?${qs}` : path
}

async function parseError(res: Response): Promise<ApiError> {
  const retryHeader = res.headers.get('retry-after')
  const retryAfter = retryHeader ? Number(retryHeader) : null
  let code = `http_${res.status}`
  let message = res.statusText || `Request failed (${res.status})`
  let details: unknown
  try {
    const body = (await res.json()) as { error?: { code?: string; message?: string; details?: unknown } }
    if (body?.error) {
      code = body.error.code ?? code
      message = body.error.message ?? message
      details = body.error.details
    }
  } catch {
    /* non-JSON body (proxy error page): keep the status text */
  }
  return new ApiError(
    res.status,
    code,
    message,
    details,
    Number.isFinite(retryAfter) && retryAfter !== null ? retryAfter : null,
  )
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, signal, query, allow401 = false } = options
  const headers: Record<string, string> = { Accept: 'application/json' }

  if (body !== undefined) headers['Content-Type'] = 'application/json'
  // Mutating verbs need the CSRF header; GETs do not and sending it is harmless,
  // but we keep it off GET so a stale token cannot turn a harmless read into a 403.
  // The value comes from the cookie the server set beside the session cookie; the server also
  // requires that same cookie to be present, so this header alone proves nothing and is not
  // trusted on its own.
  if (method !== 'GET') {
    const csrf = readCsrfCookie()
    if (csrf) headers[CSRF_HEADER] = csrf
  }

  let res: Response
  try {
    res = await fetch(buildUrl(path, query), {
      method,
      credentials: 'include',
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: signal ?? null,
      // Never cache an authenticated response.
      cache: 'no-store',
    })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    throw new ApiError(0, 'network_error', 'Cannot reach the panel. Check that the server is running and your network is up.')
  }

  if (res.status === 401 && !allow401) {
    clearSession()
  }
  if (!res.ok) throw await parseError(res)
  if (res.status === 204) return undefined as T

  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

// ------------------------------------------------------------------ endpoints
export const api = {
  // auth -------------------------------------------------------------
  me: (signal?: AbortSignal) => request<Session>('/api/auth/me', { signal, allow401: true }),

  login: (username: string, password: string) =>
    request<Session>('/api/auth/login', { method: 'POST', body: { username, password }, allow401: true }),

  logout: () => request<void>('/api/auth/logout', { method: 'POST' }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<void>('/api/auth/password', {
      method: 'POST',
      body: { current_password: currentPassword, new_password: newPassword },
    }),

  // routers ----------------------------------------------------------
  listRouters: (params: { status?: string; q?: string } = {}, signal?: AbortSignal) =>
    request<RouterListResponse>('/api/v1/routers', { query: params, signal }),

  getRouter: (id: string, signal?: AbortSignal) =>
    request<Router>(`/api/v1/routers/${encodeURIComponent(id)}`, { signal }),

  createRouter: (input: CreateRouterInput) =>
    request<RouterCreated>('/api/v1/routers', { method: 'POST', body: input }),

  updateRouter: (id: string, patch: Partial<Pick<Router, 'name' | 'group_name' | 'notes' | 'http_port'>>) =>
    request<Router>(`/api/v1/routers/${encodeURIComponent(id)}`, { method: 'PATCH', body: patch }),

  deleteRouter: (id: string) =>
    request<void>(`/api/v1/routers/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  rotateKey: (id: string) =>
    request<{ bootstrap_token: string; bootstrap_expires_at: string; install_command: string; install_script_url: string; note: string }>(
      `/api/v1/routers/${encodeURIComponent(id)}/rotate-key`,
      { method: 'POST' },
    ),

  routerStatus: (id: string, signal?: AbortSignal) =>
    request<RouterStatus>(`/api/v1/routers/${encodeURIComponent(id)}/status`, { signal }),

  installScript: (id: string, signal?: AbortSignal) =>
    request<InstallScript>(`/api/v1/routers/${encodeURIComponent(id)}/script`, { signal }),

  // console ----------------------------------------------------------
  consoleInfo: (id: string, signal?: AbortSignal) =>
    request<ConsoleInfo>(`/api/v1/routers/${encodeURIComponent(id)}/console`, { signal }),

  consoleStart: (id: string) =>
    request<ConsoleStart>(`/api/v1/routers/${encodeURIComponent(id)}/console/start`, { method: 'POST' }),

  consoleSessions: (signal?: AbortSignal) =>
    request<ConsoleSessionList>('/api/v1/console/sessions', { signal }),

  /** Admin-only: force-close one live console session. */
  terminateConsoleSession: (id: string) =>
    request<void>(`/api/v1/console/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // audit ------------------------------------------------------------
  listAudit: (
    params: { router_id?: string; action?: string; actor?: string; limit?: number; offset?: number } = {},
    signal?: AbortSignal,
  ) => request<AuditListResponse>('/api/v1/audit', { query: params, signal }),

  // users ------------------------------------------------------------
  listUsers: (signal?: AbortSignal) => request<{ items: User[]; total?: number } | User[]>('/api/v1/users', { signal }),

  createUser: (input: CreateUserInput) => request<User>('/api/v1/users', { method: 'POST', body: input }),

  updateUser: (id: number, patch: UpdateUserInput) =>
    request<User>(`/api/v1/users/${id}`, { method: 'PATCH', body: patch }),

  deleteUser: (id: number) => request<void>(`/api/v1/users/${id}`, { method: 'DELETE' }),

  // Per-router grants. Only a viewer is narrowed per router: admin and operator reach every
  // router by role (app/services/access.py), so these endpoints are only meaningful for a
  // viewer and the UI only offers them on a viewer row.
  listUserRouters: (userId: number, signal?: AbortSignal) =>
    request<UserRouterGrantList>(`/api/v1/users/${userId}/routers`, { signal }),

  /**
   * Replaces the whole grant set. The body is the complete list the caller wants, not a diff,
   * which is why the screen sends every checked id in one PUT: re-sending the same body is a
   * no-op, and a caller never has to compute additions against a snapshot it may have lost
   * track of. `request()` adds the CSRF header for a mutating verb.
   */
  setUserRouters: (userId: number, routerIds: string[]) =>
    request<UserRouterGrantList>(`/api/v1/users/${userId}/routers`, {
      method: 'PUT',
      body: { router_ids: routerIds },
    }),

  // meta -------------------------------------------------------------
  config: (signal?: AbortSignal) => request<PanelConfig>('/api/v1/config', { signal }),

  stats: (signal?: AbortSignal) => request<Stats>('/api/v1/stats', { signal }),

  // agent endpoint (admin only; the CSRF header is added by request()) ----
  // Names mirror the operations rather than the HTTP verbs so the page reads
  // as intent; each still goes through the one request() transport.
  agentEndpointSave: (input: AgentEndpointInput) =>
    request<AgentEndpointResult>('/api/v1/settings/agent-endpoint', { method: 'PUT', body: input }),

  agentEndpointReset: () =>
    request<AgentEndpointResult>('/api/v1/settings/agent-endpoint', { method: 'DELETE' }),

  agentEndpointTest: (input: AgentEndpointInput) =>
    request<AgentEndpointTest>('/api/v1/settings/agent-endpoint/test', { method: 'POST', body: input }),
}

export type { Role }

// ------------------------------------------------------------------ error text
/**
 * Turn a failure into something a human can act on. The console and wizard paths
 * care about specific codes, so those get bespoke wording; everything else falls
 * back to the server message, which is already written for operators.
 */
export function friendlyMessage(err: unknown): string {
  if (!(err instanceof ApiError)) {
    return err instanceof Error ? err.message : 'Something went wrong'
  }
  switch (err.code) {
    case 'network_error':
      return 'Cannot reach the panel. Check that the server is running and your network is up.'
    case 'invalid_credentials':
      return 'Wrong username or password.'
    case 'rate_limited':
      return `Too many attempts. Try again in ${err.retryAfter ?? DEFAULT_RETRY_AFTER} seconds.`
    case 'csrf_failed':
      return 'Your session token expired. Reload the page and sign in again.'
    case 'forbidden':
      return 'Your role does not allow this action. Ask an administrator for operator access.'
    case 'not_found':
      return 'That item no longer exists. It may have been deleted in another tab.'
    case 'validation_error':
      return err.message || 'Some fields are invalid. Check the highlighted inputs.'
    case 'console_not_ready':
      return 'The router has not installed its console key yet. Install or rotate the key, then retry.'
    case 'console_offline':
      return 'The router is offline, so no shell can be opened. Wait for the tunnel to come back.'
    case 'console_disabled':
      return 'The console is disabled for this router.'
    case 'console_busy':
      return 'Too many console sessions are open. Close one, or ask an administrator to terminate them.'
    default:
      return err.message
  }
}

/** Extracts a field-level message map from a validation_error envelope. */
export function fieldErrors(err: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  if (!(err instanceof ApiError) || !err.details) return out
  const fields = (err.details as { fields?: Array<{ loc?: unknown[]; msg?: string }> }).fields
  if (!Array.isArray(fields)) return out
  for (const f of fields) {
    // loc is ["body", "name"] or ["body", "integrations", 0]
    const key = (f.loc ?? []).filter((p) => p !== 'body')[0]
    if (typeof key === 'string' && typeof f.msg === 'string') out[key] = f.msg
  }
  return out
}

/** Builds an absolute ws:// or wss:// URL from a server-provided relative path. */
export function wsUrl(path: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${proto}//${window.location.host}${path.startsWith('/') ? path : `/${path}`}`
}
