import { useEffect, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, fieldErrors, friendlyMessage } from '../lib/api'
import type { Router, RouterStatus } from '../lib/types'
import { useAuth, useCountdown } from '../lib/hooks'
import { cn } from '../lib/cn'
import { copyText } from '../lib/clipboard'
import { openExternal, unopenableReason } from '../lib/external'
import {
  absoluteTime,
  clockDuration,
  formatMac,
  relativeTime,
  shortFingerprint,
  uptime,
} from '../lib/format'
import { TopBar } from '../components/AppShell'
import { Badge, StatusPill, pillStateFor } from '../components/Badge'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { TextField, TextAreaField } from '../components/Field'
import { ActionMenu } from '../components/Menu'
import { EmptyState, ErrorState, InlineAlert, Skeleton } from '../components/States'
import { Modal } from '../components/Modal'
import { useToast } from '../components/Toast'
import { AuditTable } from '../components/AuditTable'

const TABS = [
  { id: 'overview', label: 'Overview', icon: 'activity' },
  { id: 'install', label: 'Install', icon: 'download' },
  { id: 'audit', label: 'Audit', icon: 'audit' },
  { id: 'settings', label: 'Settings', icon: 'settings' },
] as const

type TabId = (typeof TABS)[number]['id']

const routerPath = (id: string) => '/routers/' + encodeURIComponent(id)

export function RouterDetailPage() {
  const { id = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const canWrite = user?.role === 'admin' || user?.role === 'operator'

  const activeTab = (params.get('tab') ?? 'overview') as TabId
  const tab: TabId = TABS.some((t) => t.id === activeTab) ? activeTab : 'overview'

  const routerQuery = useQuery({
    queryKey: ['router', id],
    queryFn: ({ signal }) => api.getRouter(id, signal),
    refetchInterval: 8000,
    enabled: id !== '',
  })

  const statusQuery = useQuery({
    queryKey: ['router-status', id],
    queryFn: ({ signal }) => api.routerStatus(id, signal),
    refetchInterval: 5000,
    enabled: id !== '',
  })

  const router = routerQuery.data
  const status = statusQuery.data

  // Every "open" action navigates through /__tg/enter, not to the bare public URL: the launch
  // endpoint is what converts this panel session into a cookie scoped to that router's host.
  // Falling back to router.url keeps older rows (and a proxy that has not been re-rendered yet)
  // usable - they simply take the longer way round through the login page.
  const launchUrl = router?.launch_url || router?.url

  // A public route the browser cannot parse renders perfectly but opens nothing (an IP as the
  // subdomain suffix produces exactly that), so the header action is disabled and says why
  // rather than opening a tab that cannot exist.
  const launchProblem = router?.url ? unopenableReason(launchUrl) : ''

  const [deleteOpen, setDeleteOpen] = useState(false)

  const rotateMutation = useMutation({
    mutationFn: () => api.rotateKey(id),
    onSuccess: () => {
      toast.success('Key rotated. The previous install command no longer works.')
      void queryClient.invalidateQueries({ queryKey: ['router', id] })
      void queryClient.invalidateQueries({ queryKey: ['routers'] })
      void queryClient.invalidateQueries({ queryKey: ['router-script', id] })
    },
    onError: (err) => toast.error(friendlyMessage(err)),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteRouter(id),
    onSuccess: () => {
      toast.success('Router deleted.')
      void queryClient.invalidateQueries({ queryKey: ['routers'] })
      navigate('/hosts', { replace: true })
    },
    onError: (err) => {
      setDeleteOpen(false)
      toast.error(friendlyMessage(err))
    },
  })

  const setTab = (next: TabId) => {
    const p = new URLSearchParams(params)
    if (next === 'overview') p.delete('tab')
    else p.set('tab', next)
    setParams(p, { replace: true })
  }

  if (!id) {
    return (
      <div className="flex h-full flex-col">
        <TopBar placeholder="Search…" />
        <ErrorState
          error={new Error('No router id in the URL.')}
          onRetry={() => navigate('/hosts')}
        />
      </div>
    )
  }

  if (routerQuery.error && !router) {
    return (
      <div className="flex h-full flex-col">
        <TopBar placeholder="Search…">
          <Button size="sm" icon="chevron-left" onClick={() => navigate('/hosts')}>
            Hosts
          </Button>
        </TopBar>
        <ErrorState error={routerQuery.error} onRetry={() => void routerQuery.refetch()} />
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar placeholder="Search hosts…" />

      {!router ? (
        <DetailSkeleton />
      ) : (
        <>
          <header className="border-b border-border bg-surface/30 px-4 pb-0 pt-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 text-2xs text-muted">
                  <button
                    type="button"
                    onClick={() => navigate('/hosts')}
                    className="rounded transition-colors hover:text-text"
                  >
                    Hosts
                  </button>
                  <span aria-hidden="true" className="text-border-strong">/</span>
                  {router.group_name ? (
                    <>
                      <span className="truncate">{router.group_name}</span>
                      <span aria-hidden="true" className="text-border-strong">/</span>
                    </>
                  ) : null}
                  <span className="truncate text-text">{router.name}</span>
                </div>

                <div className="mt-1.5 flex flex-wrap items-center gap-2.5">
                  <h1 className="text-lg font-semibold leading-none tracking-tight text-text">
                    {router.name}
                  </h1>
                  <StatusPill state={pillStateFor(router.status)} />
                  {router.integrations.map((it) => (
                    <Badge key={it} tone="accent" mono>
                      {it}
                    </Badge>
                  ))}
                </div>

                <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-3xs text-faint">
                  <span>{router.slug}</span>
                  <span aria-hidden="true">·</span>
                  <span>{router.hostname ?? 'no hostname yet'}</span>
                  {router.client_ip ? (
                    <>
                      <span aria-hidden="true">·</span>
                      <span>{router.client_ip}</span>
                    </>
                  ) : null}
                  <span aria-hidden="true">·</span>
                  <span>id {router.id.slice(0, 8)}</span>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <Button
                  size="sm"
                  variant="secondary"
                  icon="external"
                  disabled={!launchUrl || !router.online || launchProblem !== ''}
                  title={
                    !launchUrl
                      ? 'No public route yet'
                      : launchProblem || undefined
                  }
                  onClick={() => {
                    // The launch URL, never the bare public URL: it is the one that turns
                    // this panel session into a credential for THIS router host. Opening
                    // the bare URL is what used to bounce the operator round the login loop.
                    // The failure is reported: a host the browser cannot parse (an IP as the
                    // subdomain suffix) used to make this button appear simply dead.
                    const result = openExternal(launchUrl)
                    if (!result.ok) toast.error(result.reason)
                  }}
                >
                  Open LuCI
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  icon="terminal"
                  disabled={!router.console_ready}
                  onClick={() => navigate(routerPath(id) + '/console')}
                >
                  Console
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  icon="key"
                  disabled={!canWrite}
                  loading={rotateMutation.isPending}
                  onClick={() => rotateMutation.mutate()}
                >
                  Rotate key
                </Button>
                <ActionMenu
                  label={'More actions for ' + router.name}
                  items={[
                    {
                      label: 'Copy LuCI URL',
                      icon: 'copy',
                      disabled: !router.url,
                      disabledReason: 'No public URL yet - it appears once the tunnel is up.',
                      onSelect: async () => {
                        const ok = await copyText(router.url ?? '')
                        if (ok) toast.success('URL copied.')
                        else toast.error('Clipboard unavailable - copy it from the address bar instead.')
                      },
                    },
                    {
                      label: 'Delete router',
                      icon: 'trash',
                      danger: true,
                      disabled: !canWrite,
                      onSelect: () => setDeleteOpen(true),
                      separatorBefore: true,
                    },
                  ]}
                />
              </div>
            </div>

            <nav className="mt-3 flex gap-0.5" role="tablist" aria-label="Router sections">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  role="tab"
                  type="button"
                  aria-selected={tab === t.id}
                  onClick={() => setTab(t.id)}
                  className={cn(
                    'relative flex items-center gap-1.5 rounded-t px-3 py-2 text-xs font-medium transition-colors',
                    tab === t.id ? 'bg-bg text-text' : 'text-muted hover:bg-surface-2/60 hover:text-text',
                  )}
                >
                  <Icon name={t.icon} size={13} />
                  {t.label}
                  {tab === t.id ? (
                    <span aria-hidden="true" className="absolute inset-x-0 -bottom-px h-0.5 bg-accent" />
                  ) : null}
                </button>
              ))}
            </nav>
          </header>

          <div className="min-h-0 flex-1 overflow-y-auto bg-bg">
            {tab === 'overview' ? <OverviewTab router={router} status={status} canWrite={canWrite} /> : null}
            {tab === 'install' ? (
              <InstallTab
                router={router}
                onRotate={() => rotateMutation.mutate()}
                rotating={rotateMutation.isPending}
              />
            ) : null}
            {tab === 'audit' ? <AuditTab routerId={id} /> : null}
            {tab === 'settings' ? (
              <SettingsTab router={router} canWrite={canWrite} onDelete={() => setDeleteOpen(true)} />
            ) : null}
          </div>
        </>
      )}

      <ConfirmDelete
        open={deleteOpen}
        routerName={router?.name ?? 'this router'}
        loading={deleteMutation.isPending}
        onClose={() => setDeleteOpen(false)}
        onConfirm={() => deleteMutation.mutate()}
      />
    </div>
  )
}

function ConfirmDelete({
  open,
  routerName,
  loading,
  onClose,
  onConfirm,
}: {
  open: boolean
  routerName: string
  loading: boolean
  onClose: () => void
  onConfirm: () => void
}) {
  const [typed, setTyped] = useState('')
  useEffect(() => {
    if (!open) setTyped('')
  }, [open])
  const matches = typed.trim() === routerName

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={'Delete ' + routerName + '?'}
      description="This cannot be undone. The keys are destroyed and the tunnel is revoked immediately."
      size="sm"
      dismissOnBackdrop={false}
      tone="danger"
      footer={
        <>
          <Button onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            variant="danger"
            icon="trash"
            loading={loading}
            disabled={!matches}
            onClick={onConfirm}
          >
            Delete permanently
          </Button>
        </>
      }
    >
      <label htmlFor="confirm-name" className="tg-label">
        Type the router name to confirm
      </label>
      <input
        id="confirm-name"
        data-autofocus
        value={typed}
        onChange={(e) => setTyped(e.target.value)}
        placeholder={routerName}
        autoComplete="off"
        className="tg-input font-mono"
      />
      <p className="tg-hint">
        {matches ? (
          <span className="text-danger">The router will be deleted as soon as you confirm.</span>
        ) : (
          <>Expected: <span className="font-mono text-text">{routerName}</span></>
        )}
      </p>
    </Modal>
  )
}

/* ------------------------------------------------------------- skeleton */
function DetailSkeleton() {
  return (
    <div className="flex-1 space-y-3 p-4" aria-busy="true" aria-label="Loading router">
      <Skeleton className="h-6 w-64" />
      <Skeleton className="h-4 w-96" />
      <div className="grid gap-3 pt-3 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full" />
        ))}
      </div>
      <Skeleton className="h-64 w-full" />
    </div>
  )
}

/* ------------------------------------------------------------- overview */
function OverviewTab({
  router,
  status,
  canWrite,
}: {
  router: Router
  status: RouterStatus | undefined
  canWrite: boolean
}) {
  const toast = useToast()
  const phase = status?.phase ?? 'waiting'
  const neverConnected = !router.last_seen_at && !router.has_key
  // Same fallback as the header action: go through the launch endpoint when the panel
  // advertises one, and keep the bare URL working for older rows.
  const launchUrl = router.launch_url || router.url
  // A public route the browser cannot parse renders perfectly but opens nothing (an IP as the
  // subdomain suffix produces exactly that), so say so here instead of leaving a dead link.
  const launchProblem = router.url ? unopenableReason(launchUrl) : ''

  const cards = [
    {
      label: 'Tunnel',
      value: router.tunnel_present ? 'Up' : 'Down',
      tone: router.tunnel_present ? 'text-success' : 'text-danger',
      hint: router.reverse_port ? 'reverse port ' + router.reverse_port : 'no port allocated',
      icon: 'link' as const,
    },
    {
      label: 'LuCI health',
      value: router.health_ok === null ? 'Unknown' : router.health_ok ? 'Healthy' : 'Failing',
      tone: router.health_ok === null ? 'text-muted' : router.health_ok ? 'text-success' : 'text-warning',
      hint: router.health_ok === null ? 'no probe yet' : 'result of the last probe',
      icon: 'shield' as const,
    },
    {
      label: 'Uptime',
      value: uptime(router.uptime_seconds),
      tone: 'text-text',
      hint: router.online_since ? 'since ' + relativeTime(router.online_since) : 'not reported',
      icon: 'clock' as const,
    },
    {
      label: 'Agent',
      value: router.client_version ?? '—',
      tone: 'text-text',
      hint: router.installed ? 'agent installed' : 'awaiting first run',
      icon: 'server' as const,
    },
  ]

  return (
    <div className="space-y-4 p-4">
      {!router.has_key ? (
        <InlineAlert tone="warning" title="This router has not exchanged its key yet">
          {router.bootstrap_expires_at ? (
            <>
              A bootstrap token was issued and expires {relativeTime(router.bootstrap_expires_at)}. Run the
              install command from the Install tab
              {canWrite ? ', or rotate the key to mint a fresh one' : ''}.
            </>
          ) : (
            <>Generate an install command from the Install tab to bring it online.</>
          )}
        </InlineAlert>
      ) : null}

      {router.online && router.health_ok === false ? (
        <InlineAlert tone="warning" title="The tunnel is up but LuCI is not answering">
          The router forwards its HTTP port but the health check fails. Usually LuCI is stopped on the
          router, or it listens on a different port than{' '}
          <span className="font-mono">{router.http_port}</span>.
        </InlineAlert>
      ) : null}

      <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map((c) => (
          <div key={c.label} className="tg-card p-3.5">
            <div className="flex items-center justify-between">
              <span className="text-2xs font-medium uppercase tracking-wide text-muted">{c.label}</span>
              <Icon name={c.icon} size={13} className="text-faint" />
            </div>
            <div className={cn('mt-2 text-base font-semibold leading-none', c.tone)}>{c.value}</div>
            <div className="mt-1.5 truncate text-2xs text-faint">{c.hint}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-3 lg:grid-cols-[1fr_320px]">
        <section className="tg-card overflow-hidden">
          <h2 className="border-b border-border px-3.5 py-2.5 text-xs font-medium text-text">Host facts</h2>
          <dl className="divide-y divide-border/60">
            <FactRow label="Friendly name" value={router.name} />
            <FactRow label="Slug" value={router.slug} mono />
            <FactRow label="Group" value={router.group_name ?? 'ungrouped'} />
            <FactRow label="OS" value={router.os_type} />
            <FactRow label="System hostname" value={router.hostname} mono />
            <FactRow label="Model" value={router.model} />
            <FactRow label="Firmware" value={router.openwrt_version} mono />
            <FactRow label="MAC" value={formatMac(router.mac)} mono />
            <FactRow label="Reported IP" value={router.client_ip} mono />
            <FactRow
              label="Key fingerprint"
              value={router.key_fingerprint ? shortFingerprint(router.key_fingerprint) : null}
              mono
              title={router.key_fingerprint ?? undefined}
              badge={
                router.has_key ? (
                  <Badge tone="success" icon="key">
                    installed
                  </Badge>
                ) : (
                  <Badge tone="warning" icon="alert">
                    missing
                  </Badge>
                )
              }
            />
            <FactRow label="LuCI port on router" value={String(router.http_port)} mono />
            <FactRow label="Reverse port" value={router.reverse_port ? String(router.reverse_port) : null} mono />
            <FactRow label="Console port" value={router.console_port ? String(router.console_port) : null} mono />
            <FactRow label="Bind address" value={router.bind_address} mono />
            <FactRow label="Notes" value={router.notes} />
          </dl>
        </section>

        <div className="space-y-3">
          <section className="tg-card p-3.5">
            <h2 className="text-xs font-medium text-text">Public route</h2>
            {router.url ? (
              <div className="mt-2 space-y-1.5">
                {launchProblem ? (
                  // Not a link: the href would be a host the browser refuses, so offering it as
                  // one is a dead end that looks live. The address stays copyable above.
                  <span className="block break-all font-mono text-2xs text-muted">{router.url}</span>
                ) : (
                  <a
                    href={launchUrl ?? router.url}
                    target="_blank"
                    rel="noreferrer"
                    className="block break-all text-2xs text-accent hover:underline"
                  >
                    {router.url}
                  </a>
                )}
                <Button
                  size="sm"
                  variant="secondary"
                  icon="copy"
                  onClick={async () => {
                    const ok = await copyText(router.url ?? '')
                    if (ok) toast.success('URL copied.')
                    else toast.error('Clipboard unavailable - copy it from the address bar instead.')
                  }}
                >
                  Copy URL
                </Button>
                {launchProblem ? (
                  <InlineAlert tone="danger" title="This public route cannot be opened">
                    {launchProblem}
                  </InlineAlert>
                ) : (
                  <p className="text-3xs leading-relaxed text-faint">
                    The link signs you in to this router and lands straight in its LuCI. The address
                    itself is <span className="font-mono">{router.url}</span>: opening it in a fresh
                    browser sends you through the panel login first, which now hands you back here
                    instead of looping. The panel session never reaches the router - the route
                    gets its own short-lived cookie, scoped to this router alone.
                  </p>
                )}
              </div>
            ) : (
              <p className="mt-2 text-2xs leading-relaxed text-muted">
                No route yet. It is created automatically once the tunnel is up and the health check
                passes.
              </p>
            )}
          </section>

          <section className="tg-card p-3.5">
            <h2 className="text-xs font-medium text-text">Activity</h2>
            <dl className="mt-2 space-y-1.5">
              <TimelineRow label="Created" value={absoluteTime(router.created_at)} />
              <TimelineRow
                label="Last seen"
                value={router.last_seen_at ? relativeTime(router.last_seen_at) : 'never'}
              />
              <TimelineRow
                label="Last heartbeat"
                value={router.last_heartbeat_at ? relativeTime(router.last_heartbeat_at) : 'never'}
              />
              <TimelineRow label="Online since" value={relativeTime(router.online_since)} />
              <TimelineRow label="Updated" value={relativeTime(router.updated_at)} />
            </dl>
            {neverConnected ? (
              <p className="mt-2.5 border-t border-border pt-2 text-3xs leading-relaxed text-faint">
                Nothing has been reported yet - the panel has never seen this router.
              </p>
            ) : null}
          </section>

          <section className="tg-card p-3.5">
            <h2 className="text-xs font-medium text-text">Connection phase</h2>
            <p className="mt-1.5 flex items-center gap-1.5 text-2xs text-muted">
              <Icon
                name={phase === 'done' ? 'check-circle' : 'spinner'}
                size={12}
                className={cn(phase !== 'done' && 'animate-spin')}
              />
              {phase}
            </p>
            {status?.message ? (
              <p className="mt-2 rounded border border-border bg-surface-2 px-2 py-1.5 font-mono text-3xs text-muted">
                {status.message}
              </p>
            ) : null}
          </section>
        </div>
      </div>
    </div>
  )
}

function FactRow({
  label,
  value,
  mono,
  title,
  badge,
}: {
  label: string
  value: string | null | undefined
  mono?: boolean
  title?: string
  badge?: React.ReactNode
}) {
  return (
    <div className="flex items-center gap-3 px-3.5 py-2">
      <dt className="w-40 shrink-0 text-2xs text-muted">{label}</dt>
      <dd
        className={cn(
          'min-w-0 flex-1 truncate text-2xs text-text',
          mono && 'font-mono',
          !value && 'text-faint',
        )}
        title={title ?? value ?? undefined}
      >
        {value || '—'}
      </dd>
      {badge ? <dd className="shrink-0">{badge}</dd> : null}
    </div>
  )
}

function TimelineRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <dt className="text-2xs text-muted">{label}</dt>
      <dd className="text-2xs text-text">{value}</dd>
    </div>
  )
}

/* ------------------------------------------------------------- install */
function InstallTab({
  router,
  onRotate,
  rotating,
}: {
  router: Router
  onRotate: () => void
  rotating: boolean
}) {
  const toast = useToast()
  const scriptQuery = useQuery({
    queryKey: ['router-script', router.id],
    queryFn: ({ signal }) => api.installScript(router.id, signal),
    retry: false,
    staleTime: 0,
  })
  const { secondsLeft } = useCountdown(scriptQuery.data?.bootstrap_expires_at ?? null)

  const command = scriptQuery.data?.install_command ?? null
  const usable = Boolean(command) && secondsLeft !== null && secondsLeft > 0

  return (
    <div className="space-y-4 p-4">
      <InlineAlert tone="info" title="Install commands are single-use">
        A command carries a bootstrap token that is stored only as a SHA-256 hash and expires within
        minutes. It cannot be shown a second time. Generating a new one rotates the key and revokes the
        old command.
      </InlineAlert>

      <section className="tg-card overflow-hidden">
        <div className="flex items-center justify-between gap-2 border-b border-border px-3.5 py-2.5">
          <h2 className="text-xs font-medium text-text">Current command</h2>
          <div className="flex items-center gap-2">
            {scriptQuery.isFetching ? (
              <span className="flex items-center gap-1.5 text-3xs text-faint">
                <Icon name="spinner" size={11} className="animate-spin" /> loading
              </span>
            ) : null}
            <Button size="sm" variant="secondary" icon="key" loading={rotating} onClick={onRotate}>
              Rotate &amp; show
            </Button>
          </div>
        </div>

        {scriptQuery.isLoading ? (
          <div className="p-3.5">
            <Skeleton className="h-16 w-full" />
          </div>
        ) : usable ? (
          <>
            <div className="flex items-center justify-between gap-2 border-b border-border bg-surface-2/50 px-3.5 py-1.5">
              <span className="flex items-center gap-1.5 font-mono text-3xs text-warning">
                <Icon name="clock" size={11} />
                expires in {clockDuration(secondsLeft ?? 0)}
              </span>
              <Button
                size="sm"
                variant="secondary"
                icon="copy"
                onClick={async () => {
                  const ok = await copyText(command ?? '')
                  if (ok) toast.success('Command copied.')
                  else toast.error('Clipboard unavailable - select and copy manually.')
                }}
              >
                Copy
              </Button>
            </div>
            <pre className="overflow-x-auto p-3.5 font-mono text-2xs leading-relaxed text-text">
              <code>{command}</code>
            </pre>
          </>
        ) : (
          <div className="px-3.5 py-6 text-center">
            <div className="mx-auto mb-2 flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface-2 text-muted">
              <Icon name="key" size={16} />
            </div>
            <p className="text-xs font-medium text-text">
              {scriptQuery.data ? 'The previous command has expired' : 'No stored command'}
            </p>
            <p className="mx-auto mt-1 max-w-md text-2xs leading-relaxed text-muted">
              {scriptQuery.data
                ? 'Bootstrap tokens are short-lived. Rotate the key to mint a fresh command - the router keeps its identity and only re-registers.'
                : 'Commands are not kept on the server after they are issued. Rotate the key to generate one for this router.'}
            </p>
            <Button
              className="mt-3"
              size="sm"
              variant="primary"
              icon="key"
              loading={rotating}
              onClick={onRotate}
            >
              Rotate &amp; show command
            </Button>
          </div>
        )}
      </section>

      <section className="tg-card p-3.5">
        <h2 className="text-xs font-medium text-text">What the installer does</h2>
        <ol className="mt-2 space-y-2">
          {[
            [
              'Exchanges the token',
              'Posts the single-use token and stores the returned API token plus its own ed25519 private key locally. The private key never leaves the router.',
            ],
            [
              'Opens the reverse tunnel',
              'Runs ssh -N -R against the allocated reverse port, with keepalives and a supervisor (procd or rc.d) so it restarts on drop.',
            ],
            [
              'Sends a heartbeat',
              'Reports hostname, model, firmware and uptime so this page stays current.',
            ],
            [
              'Enables the console',
              'Registers a second key so the panel can open an interactive shell when you ask for it.',
            ],
          ].map(([title, body], i) => (
            <li key={title} className="flex gap-2.5">
              <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-border-strong bg-surface-2 font-mono text-3xs text-muted">
                {i + 1}
              </span>
              <div className="min-w-0">
                <div className="text-2xs font-medium text-text">{title}</div>
                <div className="mt-0.5 text-3xs leading-relaxed text-muted">{body}</div>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="tg-card p-3.5">
        <h2 className="text-xs font-medium text-text">Ports assigned to this router</h2>
        <div className="mt-2 grid gap-2 sm:grid-cols-3">
          <PortBox label="LuCI on router" value={router.http_port} />
          <PortBox label="Reverse tunnel" value={router.reverse_port} />
          <PortBox label="Console" value={router.console_port} />
        </div>
        <p className="mt-2 text-3xs leading-relaxed text-faint">
          Ports are allocated from the panel pool and stay stable for this router. Deleting the router
          returns them to the pool.
        </p>
      </section>
    </div>
  )
}

function PortBox({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="rounded border border-border bg-surface-2 px-2.5 py-2">
      <div className="text-3xs uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-0.5 font-mono text-sm text-text">{value ?? '—'}</div>
    </div>
  )
}

/* ------------------------------------------------------------- audit */
function AuditTab({ routerId }: { routerId: string }) {
  const navigate = useNavigate()
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['audit', 'router', routerId],
    queryFn: ({ signal }) => api.listAudit({ router_id: routerId, limit: 50 }, signal),
    refetchInterval: 15_000,
  })

  if (error) return <ErrorState error={error} onRetry={() => void refetch()} />

  const items = data?.items ?? []
  if (!isLoading && items.length === 0) {
    return (
      <EmptyState
        icon="audit"
        title="No activity recorded for this router"
        description="Rotating the key, opening a console or changing settings is logged here."
      />
    )
  }

  return (
    <div className="p-4">
      <div className="tg-card overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-3.5 py-2.5">
          <h2 className="text-xs font-medium text-text">Recent activity</h2>
          <span className="text-3xs text-faint">{data?.total ?? 0} entries</span>
        </div>
        <AuditTable
          entries={items}
          loading={isLoading}
          showRouter={false}
          onRouterClick={(nextId) => navigate(routerPath(nextId))}
        />
      </div>
    </div>
  )
}

/* ------------------------------------------------------------- settings */
function SettingsTab({
  router,
  canWrite,
  onDelete,
}: {
  router: Router
  canWrite: boolean
  onDelete: () => void
}) {
  const toast = useToast()
  const queryClient = useQueryClient()
  const [name, setName] = useState(router.name)
  const [group, setGroup] = useState(router.group_name ?? '')
  const [notes, setNotes] = useState(router.notes ?? '')
  const [httpPort, setHttpPort] = useState(String(router.http_port))
  const [errors, setErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    setName(router.name)
    setGroup(router.group_name ?? '')
    setNotes(router.notes ?? '')
    setHttpPort(String(router.http_port))
  }, [router])

  const dirty =
    name !== router.name ||
    group !== (router.group_name ?? '') ||
    notes !== (router.notes ?? '') ||
    httpPort !== String(router.http_port)

  const mutation = useMutation({
    mutationFn: () =>
      api.updateRouter(router.id, {
        name: name.trim(),
        group_name: group.trim() || null,
        notes: notes.trim() || null,
        http_port: Number(httpPort) || 80,
      }),
    onSuccess: () => {
      setErrors({})
      toast.success('Router updated.')
      void queryClient.invalidateQueries({ queryKey: ['router', router.id] })
      void queryClient.invalidateQueries({ queryKey: ['routers'] })
    },
    onError: (err) => {
      const fields = fieldErrors(err)
      if (Object.keys(fields).length > 0) setErrors(fields)
      else toast.error(friendlyMessage(err))
    },
  })

  const reset = () => {
    setName(router.name)
    setGroup(router.group_name ?? '')
    setNotes(router.notes ?? '')
    setHttpPort(String(router.http_port))
    setErrors({})
  }

  return (
    <div className="max-w-2xl space-y-4 p-4">
      {!canWrite ? (
        <InlineAlert tone="info" title="Read-only account">
          Your role can view routers but not change them. Ask an administrator for operator access.
        </InlineAlert>
      ) : null}

      <form
        className="tg-card p-3.5"
        onSubmit={(e) => {
          e.preventDefault()
          if (!name.trim()) {
            setErrors({ name: 'A name is required.' })
            return
          }
          mutation.mutate()
        }}
        noValidate
      >
        <h2 className="text-xs font-medium text-text">Identity</h2>
        <p className="mt-0.5 text-2xs text-muted">
          How this router appears in the host list and in audit entries.
        </p>

        <div className="mt-3 space-y-3">
          <TextField
            label="Friendly Name"
            name="name"
            required
            value={name}
            maxLength={128}
            disabled={!canWrite}
            error={errors.name}
            onChange={(e) => setName(e.target.value)}
          />
          <TextField
            label="Group"
            name="group_name"
            value={group}
            maxLength={64}
            disabled={!canWrite}
            error={errors.group_name}
            onChange={(e) => setGroup(e.target.value)}
            hint="Free-form. Used for filtering on the host list."
          />
          <TextField
            label="LuCI HTTP port"
            name="http_port"
            type="number"
            min={1}
            max={65535}
            value={httpPort}
            disabled={!canWrite}
            error={errors.http_port}
            onChange={(e) => setHttpPort(e.target.value)}
            hint="Changing this does not touch the router - update LuCI there too."
          />
          <TextAreaField
            label="Notes"
            name="notes"
            value={notes}
            rows={3}
            disabled={!canWrite}
            onChange={(e) => setNotes(e.target.value)}
          />
        </div>

        <div className="mt-4 flex items-center justify-end gap-2 border-t border-border pt-3">
          {dirty ? (
            <span className="mr-auto text-3xs text-warning">unsaved changes</span>
          ) : (
            <span className="mr-auto text-3xs text-faint">no changes</span>
          )}
          <Button size="sm" onClick={reset} disabled={!dirty || mutation.isPending}>
            Discard
          </Button>
          <Button
            size="sm"
            type="submit"
            variant="primary"
            loading={mutation.isPending}
            disabled={!canWrite || !dirty}
          >
            Save changes
          </Button>
        </div>
      </form>

      <section className="rounded-lg border border-danger/30 bg-danger/[0.04] p-3.5">
        <h2 className="flex items-center gap-1.5 text-xs font-medium text-danger">
          <Icon name="alert" size={13} />
          Danger zone
        </h2>
        <p className="mt-1 text-2xs leading-relaxed text-muted">
          Deleting this router removes its keys, revokes the tunnel, closes the proxy route and returns
          its ports to the pool. The router itself is untouched, but its agent will fail on every
          heartbeat until it is reinstalled.
        </p>
        <Button
          className="mt-2.5"
          size="sm"
          variant="danger"
          icon="trash"
          disabled={!canWrite}
          onClick={onDelete}
        >
          Delete router
        </Button>
      </section>
    </div>
  )
}
