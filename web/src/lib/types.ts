/** Wire types. Mirrors app/schemas.py exactly - if the API adds a field, add it here. */

export type Role = 'admin' | 'operator' | 'viewer'
export type OsType = 'linux' | 'freebsd' | 'windows'
export type RouterState = 'pending' | 'awaiting' | 'online' | 'offline'
export type WizardPhase = 'waiting' | 'connected' | 'reporting' | 'done' | 'offline'

export interface User {
  id: number
  username: string
  display_name: string | null
  role: Role
  is_active: boolean
  created_at: string | null
  last_login_at: string | null
}

export interface Session {
  user: User
  csrf_token: string
  expires_at: string | null
}

export interface Router {
  id: string
  name: string
  slug: string
  group_name: string | null
  integrations: string[]
  os_type: string
  notes: string | null
  status: string
  online: boolean
  http_port: number
  remote_port: number | null
  reverse_port: number | null
  console_port: number | null
  console_ready: boolean
  bind_address: string | null
  url: string | null
  /** The clickable form of `url`: it goes through /__tg/enter, which installs a cookie scoped
   *  to that router's host. `url` alone cannot authenticate from a fresh browser. */
  launch_url: string | null
  hostname: string | null
  model: string | null
  openwrt_version: string | null
  mac: string | null
  client_ip: string | null
  client_version: string | null
  uptime_seconds: number | null
  key_fingerprint: string | null
  has_key: boolean
  installed: boolean
  tunnel_present: boolean
  health_ok: boolean | null
  created_at: string | null
  updated_at: string | null
  last_seen_at: string | null
  last_heartbeat_at: string | null
  online_since: string | null
  bootstrap_expires_at: string | null
}

export interface RouterCreated extends Router {
  bootstrap_token: string
  bootstrap_expires_at: string
  install_command: string
  install_script_url: string
}

export interface RotateKeyResult {
  bootstrap_token: string
  bootstrap_expires_at: string
  install_command: string
  install_script_url: string
  note: string
}

export interface RouterListResponse {
  items: Router[]
  total: number
  online: number
  offline: number
  pending: number
}

export interface RouterStatus {
  id: string
  status: string
  phase: WizardPhase
  online: boolean
  tunnel_present: boolean
  health_ok: boolean | null
  last_seen_at: string | null
  last_heartbeat_at: string | null
  message: string | null
}

export interface InstallScript {
  install_command: string
  bootstrap_token: string
  bootstrap_expires_at: string
  install_script_url: string
}

export interface AuditEntry {
  id: number
  ts: string | null
  actor_username: string | null
  action: string
  outcome: string
  router_id: string | null
  router_name: string | null
  ip: string | null
  detail: string | null
}

export interface AuditListResponse {
  items: AuditEntry[]
  total: number
}

export type AgentScheme = 'http' | 'https'

/** Where the panel lives from its own point of view, and where it came from. */
export interface AgentEndpoint {
  scheme: AgentScheme
  host: string
  /** null means "the scheme default" (80 for http, 443 for https). */
  port: number | null
  source: 'environment' | 'database'
  /**
   * True = the router verifies the panel's certificate. False = the operator accepted a
   * self-signed one, so the router cannot tell the panel from an impostor.
   *
   * The server forces this to true on an http endpoint: there is no certificate to check, and
   * a stored false there would be a claim the router could not act on. The UI therefore never
   * sends false over http - see the checkbox in Settings.
   */
  verify_tls: boolean
}

/** Body of PUT/DELETE/POST /api/v1/settings/agent-endpoint. */
export interface AgentEndpointInput {
  scheme: AgentScheme
  host: string
  port: number | null
  /** Sent on save AND on the probe: the probe must test the policy about to be saved. */
  verify_tls: boolean
}

/** 200 body of the save and the reset. */
export interface AgentEndpointResult {
  agent_url: string
  agent_endpoint: AgentEndpoint
}

/** 200 body of the reachability probe. */
export interface AgentEndpointTest {
  ok: boolean
  checked_url: string
  status_code: number | null
  latency_ms: number | null
  error: string | null
}

export interface PanelConfig {
  panel_url: string
  /** Effective base URL routers dial. May differ from panel_url when overridden. */
  agent_url: string
  /** Null when the panel has no usable endpoint at all (an unparsable panel_url, nothing stored). */
  agent_endpoint: AgentEndpoint | null
  /** False when the panel has no hostname to probe, so "Test connection" cannot work. */
  agent_endpoint_testable: boolean
  subdomain_suffix: string
  /** "subdomain" (one host per router) or "path" (one gateway host, /<slug>/ per router). */
  route_mode: string
  /** The single host routers are published under in path mode; empty otherwise. */
  gateway_host: string
  bootstrap_ttl_minutes: number
  poll_interval_seconds: number
  proxy_driver: string
  version: string
}

export interface Stats {
  routers_total: number
  routers_online: number
  routers_offline: number
  routers_pending: number
  ports_free: number
  users_total: number
  console_sessions_active: number
}

export type ConsoleState = 'disabled' | 'no_key' | 'not_installed' | 'ready' | 'offline'

export interface ConsoleInfo {
  state: ConsoleState
  console_port: number | null
  installed_at: string | null
  fingerprint: string | null
  active_sessions: number
  idle_timeout_seconds: number
  max_session_seconds: number
}

export interface ConsoleStart {
  router_id: string
  ticket: string
  ws_path: string
  expires_at: string
  console_port: number
}

export interface ConsoleSession {
  id: string
  router_id: string
  router_name: string | null
  username: string | null
  client_ip: string | null
  started_at: string | null
  closed_at: string | null
  close_reason: string | null
  bytes_in: number
  bytes_out: number
}

export interface ConsoleSessionList {
  items: ConsoleSession[]
  total: number
}

export interface CreateRouterInput {
  name: string
  slug?: string | null
  group_name?: string | null
  integrations?: string[]
  os_type: OsType
  notes?: string | null
  http_port?: number
}

export interface CreateUserInput {
  username: string
  password: string
  display_name?: string | null
  role: Role
}

export interface UpdateUserInput {
  display_name?: string | null
  role?: Role
  is_active?: boolean
  password?: string
}
