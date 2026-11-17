import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'
import { api, friendlyMessage, wsUrl } from '../lib/api'
import type { ConsoleInfo, ConsoleSession } from '../lib/types'
import { useAuth, useCountdown } from '../lib/hooks'
import { cn } from '../lib/cn'
import { absoluteTime, bytes, clockDuration, relativeTime } from '../lib/format'
import { TopBar } from '../components/AppShell'
import { StatusPill, pillStateFor } from '../components/Badge'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import type { IconName } from '../components/Icon'
import { EmptyState, ErrorState, InlineAlert, Skeleton, Spinner } from '../components/States'
import { useToast } from '../components/Toast'

type LinkState = 'idle' | 'opening' | 'open' | 'closed' | 'error'

const STATE_COPY: Record<LinkState, { label: string; tone: string; dot: string }> = {
  idle: { label: 'not connected', tone: 'text-muted', dot: 'bg-faint' },
  opening: { label: 'connecting', tone: 'text-warning', dot: 'bg-warning animate-pulse' },
  open: { label: 'connected', tone: 'text-success', dot: 'bg-success' },
  closed: { label: 'disconnected', tone: 'text-muted', dot: 'bg-faint' },
  error: { label: 'connection failed', tone: 'text-danger', dot: 'bg-danger' },
}

function cssColor(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  if (!raw) return fallback
  const parts = raw.split(/[\s,]+/).map((p) => Number(p))
  if (parts.length >= 3 && parts.every((n) => Number.isFinite(n))) {
    return 'rgb(' + parts[0] + ', ' + parts[1] + ', ' + parts[2] + ')'
  }
  return raw
}

function terminalTheme() {
  return {
    background: cssColor('--tg-bg', '#0b0f19'),
    foreground: cssColor('--tg-text', '#e5e7eb'),
    cursor: cssColor('--tg-accent', '#3b82f6'),
    cursorAccent: cssColor('--tg-bg', '#0b0f19'),
    selectionBackground: cssColor('--tg-accent-soft', 'rgba(59,130,246,0.30)'),
    black: cssColor('--tg-surface', '#121826'),
    red: cssColor('--tg-danger', '#ef4444'),
    green: cssColor('--tg-success', '#22c55e'),
    yellow: cssColor('--tg-warning', '#f59e0b'),
    blue: cssColor('--tg-accent', '#3b82f6'),
    magenta: '#a855f7',
    cyan: '#06b6d4',
    white: cssColor('--tg-text', '#e5e7eb'),
    brightBlack: cssColor('--tg-faint', '#64748b'),
  }
}

export function ConsolePage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const { user } = useAuth()
  const canOpen = user?.role === 'admin' || user?.role === 'operator'

  const infoQuery = useQuery({
    queryKey: ['console-info', id],
    queryFn: ({ signal }) => api.consoleInfo(id, signal),
    refetchInterval: 10_000,
    enabled: id !== '',
    retry: false,
  })

  const routerQuery = useQuery({
    queryKey: ['router', id],
    queryFn: ({ signal }) => api.getRouter(id, signal),
    enabled: id !== '',
    retry: false,
  })

  const sessionsQuery = useQuery({
    queryKey: ['console-sessions'],
    queryFn: ({ signal }) => api.consoleSessions(signal),
    refetchInterval: 15_000,
    retry: false,
  })

  const info = infoQuery.data
  const router = routerQuery.data

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar placeholder="Search hosts…">
        <Button size="sm" variant="secondary" icon="chevron-left" onClick={() => navigate('/routers/' + encodeURIComponent(id))}>
          Back to router
        </Button>
      </TopBar>

      <div className="flex min-h-0 flex-1 flex-col">
        <header className="border-b border-border px-4 py-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Icon name="terminal" size={14} className="text-accent" />
                <h1 className="truncate text-sm font-semibold text-text">
                  {router?.name ?? 'Router console'}
                </h1>
                {router ? <StatusPill state={pillStateFor(router.status)} /> : null}
                {info ? (
                  <span className="font-mono text-3xs text-faint">
                    port {info.console_port ?? '—'}
                  </span>
                ) : null}
              </div>
              <p className="mt-0.5 text-3xs text-faint">
                Interactive shell over the existing tunnel. Every keystroke is recorded as a console
                session and audited.
              </p>
            </div>
          </div>
        </header>

        {infoQuery.isLoading ? (
          <ConsoleSkeleton />
        ) : infoQuery.error && !info ? (
          <ErrorState error={infoQuery.error} onRetry={() => void infoQuery.refetch()} />
        ) : info && info.state !== 'ready' ? (
          <ConsoleGate info={info} routerId={id} canOpen={canOpen} />
        ) : !canOpen ? (
          <div className="p-4">
            <InlineAlert tone="info" title="Your role cannot open a console">
              Interactive shells require the operator or administrator role. Ask an administrator to
              raise your access, or ask a colleague to run the command for you.
            </InlineAlert>
          </div>
        ) : info ? (
          <ConsoleTerminal info={info} routerId={id} onDisconnectToast={(msg) => toast.info(msg)} />
        ) : null}

        <RecentSessions
          sessions={(sessionsQuery.data?.items ?? []).filter((s) => s.router_id === id)}
          loading={sessionsQuery.isLoading}
        />
      </div>
    </div>
  )
}

/* --------------------------------------------------------------- gate */
const GATE_COPY: Record<
  Exclude<ConsoleInfo['state'], 'ready'>,
  { icon: IconName; title: string; body: string }
> = {
  disabled: {
    icon: 'shield',
    title: 'The console is disabled on the panel',
    body: 'An administrator turned the web console off (TUNNELGATE_CONSOLE_ENABLED=false). Tunnels and the LuCI proxy are unaffected - use ssh from a jump host if you need a shell.',
  },
  no_key: {
    icon: 'key',
    title: 'No console key yet',
    body: 'The panel mints the console key pair lazily, the first time somebody asks for a shell. Press "Prepare console" below and the key is created; the router installs the public half on its next heartbeat, usually within a minute.',
  },
  not_installed: {
    icon: 'clock',
    title: 'Waiting for the router to install the console key',
    body: 'The key exists on the panel but the router has not confirmed it yet. That happens on the next heartbeat, which runs about once a minute. If the router is offline, it will only pick the key up when it reconnects.',
  },
  offline: {
    icon: 'wifi-off',
    title: 'The router is offline',
    body: 'A console is opened through the reverse tunnel, so the router has to be online first. Bring the tunnel back and this page will unblock on its own.',
  },
}

function ConsoleGate({
  info,
  routerId,
  canOpen,
}: {
  info: ConsoleInfo
  routerId: string
  canOpen: boolean
}) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const copy = GATE_COPY[info.state === 'ready' ? 'disabled' : info.state]

  const prepare = async () => {
    setBusy(true)
    try {
      await api.consoleStart(routerId)
      toast.success('Console key created. The shell unlocks as soon as the router confirms the key.')
    } catch (err) {
      toast.error(friendlyMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-4">
      <div className="tg-card mx-auto max-w-xl p-5 text-center">
        <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl border border-border bg-surface-2 text-muted">
          <Icon name={copy.icon} size={20} />
        </div>
        <h2 className="mt-3 text-sm font-semibold text-text">{copy.title}</h2>
        <p className="mx-auto mt-1.5 max-w-md text-2xs leading-relaxed text-muted">{copy.body}</p>

        {info.state === 'no_key' && canOpen ? (
          <Button
            className="mt-4"
            variant="primary"
            icon="key"
            loading={busy}
            onClick={() => void prepare()}
          >
            Prepare console
          </Button>
        ) : null}

        <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-1.5 border-t border-border pt-3 text-left">
          <GateFact label="Console port" value={info.console_port === null ? '—' : String(info.console_port)} />
          <GateFact label="Active sessions" value={String(info.active_sessions)} />
          <GateFact
            label="Idle timeout"
            value={info.idle_timeout_seconds > 0 ? clockDuration(info.idle_timeout_seconds) : 'off'}
          />
          <GateFact label="Max duration" value={clockDuration(info.max_session_seconds)} />
        </dl>
      </div>
    </div>
  )
}

function GateFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <dt className="text-3xs text-muted">{label}</dt>
      <dd className="font-mono text-3xs text-text">{value}</dd>
    </div>
  )
}

/* ----------------------------------------------------------- terminal */
function ConsoleTerminal({
  info,
  routerId,
  onDisconnectToast,
}: {
  info: ConsoleInfo
  routerId: string
  onDisconnectToast: (msg: string) => void
}) {
  const hostRef = useRef<HTMLDivElement | null>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const closingRef = useRef(false)

  const [state, setState] = useState<LinkState>('idle')
  const [error, setError] = useState<string | null>(null)
  const [expiry, setExpiry] = useState<string | null>(null)
  const [startedAt, setStartedAt] = useState<number | null>(null)
  const [sessionEnd, setSessionEnd] = useState<string | null>(null)

  const { secondsLeft: ticketLeft } = useCountdown(expiry)
  const ticketExpired = expiry !== null && ticketLeft !== null && ticketLeft <= 0

  /* terminal instance: created once, survives reconnects */
  useEffect(() => {
    const host = hostRef.current
    if (!host) return
    const term = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily:
        'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      lineHeight: 1.35,
      scrollback: 5000,
      theme: terminalTheme(),
      allowProposedApi: true,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.loadAddon(new WebLinksAddon())
    term.open(host)
    termRef.current = term
    fitRef.current = fit

    const raf = requestAnimationFrame(() => {
      try {
        fit.fit()
      } catch {
        /* container not laid out yet */
      }
    })

    const observer = new ResizeObserver(() => {
      try {
        fit.fit()
      } catch {
        /* ignore */
      }
      sendResize()
    })
    observer.observe(host)

    term.writeln('\x1b[38;5;244mTunnelGate console - press Connect to open a shell.\x1b[0m')
    term.writeln('\x1b[38;5;244mThe shell runs on the router itself; the panel only relays bytes.\x1b[0m')

    return () => {
      cancelAnimationFrame(raf)
      observer.disconnect()
      try {
        wsRef.current?.close()
      } catch {
        /* ignore */
      }
      term.dispose()
      termRef.current = null
      fitRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const sendResize = useCallback(() => {
    const term = termRef.current
    const ws = wsRef.current
    if (!term || !ws || ws.readyState !== WebSocket.OPEN) return
    try {
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
    } catch {
      /* socket died between the check and the send */
    }
  }, [])

  const disconnect = useCallback((label: string) => {
    closingRef.current = true
    try {
      wsRef.current?.close()
    } catch {
      /* ignore */
    }
    wsRef.current = null
    setState('closed')
    setStartedAt(null)
    setSessionEnd(null)
    setExpiry(null)
    termRef.current?.writeln('')
    termRef.current?.writeln('\x1b[38;5;244m' + label + '\x1b[0m')
  }, [])

  const connect = useCallback(async () => {
    const term = termRef.current
    if (!term) return
    setError(null)
    setState('opening')
    closingRef.current = false

    let start
    try {
      start = await api.consoleStart(routerId)
    } catch (err) {
      setState('error')
      const msg = friendlyMessage(err)
      setError(msg)
      term.writeln('\x1b[31m' + msg + '\x1b[0m')
      return
    }

    setExpiry(start.expires_at)

    let ws: WebSocket
    try {
      ws = new WebSocket(wsUrl(start.ws_path))
      ws.binaryType = 'arraybuffer'
    } catch (err) {
      setState('error')
      setError('The browser refused to open the WebSocket: ' + String(err))
      return
    }
    wsRef.current = ws

    ws.onopen = () => {
      setState('open')
      setStartedAt(Date.now())
      term.writeln('\x1b[32mconnected\x1b[0m')
      onDisconnectToast('Console connected.')
      try {
        fitRef.current?.fit()
      } catch {
        /* ignore */
      }
      sendResize()
      term.focus()
    }

    ws.onmessage = (event: MessageEvent) => {
      const data: unknown = event.data
      if (typeof data === 'string') {
        let payload: unknown = null
        try {
          payload = JSON.parse(data)
        } catch {
          term.write(data)
          return
        }
        const frame = payload as { type?: string; message?: string; reason?: string; code?: number }
        if (frame.type === 'resize') return
        if (frame.type === 'status') {
          if (frame.message) term.writeln('\r\n\x1b[38;5;244m' + frame.message + '\x1b[0m')
          return
        }
        if (frame.type === 'exit') {
          const reason = frame.reason ?? frame.message ?? 'the remote shell exited'
          term.writeln('\r\n\x1b[38;5;244m' + reason + '\x1b[0m')
          return
        }
        if (frame.message) term.writeln('\r\n\x1b[38;5;244m' + frame.message + '\x1b[0m')
        return
      }
      if (data instanceof ArrayBuffer) {
        term.write(new Uint8Array(data))
        return
      }
      if (ArrayBuffer.isView(data)) {
        term.write(new Uint8Array(data.buffer as ArrayBuffer, data.byteOffset, data.byteLength))
      }
    }

    ws.onerror = () => {
      setState('error')
      setError('The console socket reported an error. The ticket may have expired - press Connect again.')
    }

    ws.onclose = (event: CloseEvent) => {
      const reason = event.reason ? ' (' + event.reason + ')' : ''
      const wasIntentional = closingRef.current
      wsRef.current = null
      setStartedAt(null)
      setSessionEnd(null)
      if (!wasIntentional) {
        setState(event.code === 1000 ? 'closed' : 'error')
        if (event.code !== 1000) {
          setError('Connection closed' + reason + ' - code ' + event.code + '.')
        }
        term.writeln('\r\n\x1b[38;5;244mdisconnected' + reason + '\x1b[0m')
      }
    }

    term.onData((chunk: string) => {
      const socket = wsRef.current
      if (!socket || socket.readyState !== WebSocket.OPEN) return
      socket.send(new TextEncoder().encode(chunk))
    })
  }, [routerId, sendResize, onDisconnectToast])

  const elapsed = useElapsed(startedAt)
  const maxSeconds = info.max_session_seconds
  const remaining = startedAt !== null && maxSeconds > 0 ? Math.max(0, maxSeconds - elapsed) : null

  useEffect(() => {
    if (remaining === 0) setSessionEnd('Maximum session duration reached.')
  }, [remaining])

  const copy = STATE_COPY[state]

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 p-3">
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-1.5">
        <span className="flex items-center gap-1.5">
          <span aria-hidden="true" className={cn('h-1.5 w-1.5 rounded-full', copy.dot)} />
          <span className={cn('text-2xs font-medium', copy.tone)}>{copy.label}</span>
        </span>

        {state === 'open' ? (
          <>
            <span className="h-3 w-px bg-border" aria-hidden="true" />
            <span className="font-mono text-3xs text-muted">session {clockDuration(elapsed)}</span>
            {remaining !== null ? (
              <span
                className={cn(
                  'font-mono text-3xs',
                  remaining < 60 ? 'text-danger' : remaining < 300 ? 'text-warning' : 'text-muted',
                )}
              >
                {clockDuration(remaining)} left
              </span>
            ) : null}
          </>
        ) : null}

        {state === 'opening' && ticketLeft !== null ? (
          <span className="font-mono text-3xs text-warning">ticket {ticketLeft}s</span>
        ) : null}

        {sessionEnd ? (
          <span className="text-3xs text-warning">{sessionEnd}</span>
        ) : null}

        <span className="ml-auto flex items-center gap-1.5">
          {state === 'open' ? (
            <>
              <Button size="sm" variant="secondary" icon="copy" onClick={() => termRef.current?.selectAll()}>
                Select all
              </Button>
              <Button size="sm" variant="danger" icon="x" onClick={() => disconnect('connection closed by you')}>
                Disconnect
              </Button>
            </>
          ) : (
            <Button
              size="sm"
              variant="primary"
              icon="terminal"
              loading={state === 'opening'}
              onClick={() => void connect()}
            >
              {state === 'closed' || state === 'error' ? 'Reconnect' : 'Connect'}
            </Button>
          )}
        </span>
      </div>

      {ticketExpired && state !== 'open' ? (
        <InlineAlert tone="warning" title="The one-time ticket expired">
          Tickets live for about 30 seconds. Press Connect again to mint a new one - nothing is broken.
        </InlineAlert>
      ) : null}

      {error && state !== 'open' ? (
        <InlineAlert tone="danger" title="Console connection failed">
          {error}
        </InlineAlert>
      ) : null}

      <div
        className="relative min-h-0 flex-1 overflow-hidden rounded-lg border border-border bg-bg"
        style={{ minHeight: '18rem' }}
      >
        <div ref={hostRef} className="h-full w-full pl-2 pt-2" />
        {state === 'idle' ? (
          <div className="pointer-events-none absolute inset-0 flex items-end justify-center pb-6">
            <span className="pointer-events-auto rounded-full border border-border bg-surface/90 px-3 py-1 text-3xs text-muted backdrop-blur">
              Press <span className="tg-kbd">Connect</span> to open a shell on this router
            </span>
          </div>
        ) : null}
        {state === 'opening' ? (
          <div className="absolute inset-0 flex items-center justify-center bg-bg/60 backdrop-blur-sm">
            <span className="flex items-center gap-2 rounded-lg border border-border bg-surface px-3 py-2 text-2xs text-muted">
              <Spinner size={13} /> opening the tunnel channel…
            </span>
          </div>
        ) : null}
      </div>

      <p className="px-1 text-3xs leading-relaxed text-faint">
        Idle sessions close after {info.idle_timeout_seconds > 0 ? clockDuration(info.idle_timeout_seconds) : 'never'};
        hard limit {clockDuration(maxSeconds)}. The connection travels panel → reverse tunnel → dropbear
        on the router, and the session row records who opened it and from where.
      </p>
    </div>
  )
}

function useElapsed(startedAt: number | null): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (startedAt === null) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [startedAt])
  if (startedAt === null) return 0
  return Math.max(0, Math.floor((now - startedAt) / 1000))
}

/* ------------------------------------------------------------ sessions */
function RecentSessions({ sessions, loading }: { sessions: ConsoleSession[]; loading: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const rows = useMemo(() => (expanded ? sessions : sessions.slice(0, 4)), [sessions, expanded])

  if (loading) {
    return (
      <div className="border-t border-border p-3">
        <Skeleton className="h-5 w-40" />
      </div>
    )
  }
  if (sessions.length === 0) {
    return (
      <div className="border-t border-border">
        <EmptyState
          icon="terminal"
          title="No console sessions yet"
          description="Every shell opened on this router is listed here with its byte counters and close reason."
        />
      </div>
    )
  }

  return (
    <section className="max-h-56 shrink-0 overflow-y-auto border-t border-border bg-surface/30">
      <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-surface/90 px-3.5 py-1.5 backdrop-blur">
        <h2 className="text-2xs font-medium uppercase tracking-wide text-muted">
          Console sessions ({sessions.length})
        </h2>
        {sessions.length > 4 ? (
          <button
            type="button"
            className="text-3xs text-accent hover:underline"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? 'show fewer' : 'show all'}
          </button>
        ) : null}
      </div>
      <table className="w-full text-left">
        <thead>
          <tr className="text-3xs uppercase tracking-wide text-faint">
            <th scope="col" className="px-3.5 py-1 font-medium">User</th>
            <th scope="col" className="px-3.5 py-1 font-medium">From</th>
            <th scope="col" className="px-3.5 py-1 font-medium">Started</th>
            <th scope="col" className="px-3.5 py-1 font-medium">Duration</th>
            <th scope="col" className="px-3.5 py-1 font-medium">Traffic</th>
            <th scope="col" className="px-3.5 py-1 font-medium">Closed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => (
            <tr key={s.id} className="border-t border-border/50">
              <td className="px-3.5 py-1.5 text-2xs text-text">{s.username ?? '—'}</td>
              <td className="px-3.5 py-1.5 font-mono text-3xs text-muted">{s.client_ip ?? '—'}</td>
              <td className="px-3.5 py-1.5 text-3xs text-muted" title={absoluteTime(s.started_at)}>
                {relativeTime(s.started_at)}
              </td>
              <td className="px-3.5 py-1.5 font-mono text-3xs text-muted">
                {s.started_at && s.closed_at
                  ? clockDuration(
                      Math.max(
                        0,
                        Math.round(
                          (new Date(s.closed_at).getTime() - new Date(s.started_at).getTime()) / 1000,
                        ),
                      ),
                    )
                  : 'open'}
              </td>
              <td className="px-3.5 py-1.5 font-mono text-3xs text-muted">
                {bytes(s.bytes_in)} / {bytes(s.bytes_out)}
              </td>
              <td className="px-3.5 py-1.5 text-3xs text-muted">{s.close_reason ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function ConsoleSkeleton() {
  return (
    <div className="flex-1 space-y-2 p-3" aria-busy="true" aria-label="Loading console">
      <Skeleton className="h-8 w-full" />
      <Skeleton className="h-72 w-full" />
    </div>
  )
}
