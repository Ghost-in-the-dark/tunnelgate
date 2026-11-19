import { useCallback, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, friendlyMessage } from '../lib/api'
import type { Router } from '../lib/types'
import { useAuth, useDebounced, useLocalStorage, useNow } from '../lib/hooks'
import { cn } from '../lib/cn'
import { pluralize } from '../lib/format'
import { FleetCounters, TopBar } from '../components/AppShell'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { Kpi } from '../components/Kpi'
import { openExternal } from '../lib/external'
import { HostsTable, COLUMNS } from '../components/HostsTable'
import type { ColumnId, Sort, SortKey } from '../components/HostsTable'
import { EmptyState, ErrorState, InlineAlert, TableSkeleton } from '../components/States'
import { ConfirmDialog, Modal } from '../components/Modal'
import { useToast } from '../components/Toast'
import { copyText } from '../lib/clipboard'

const STATUS_FILTERS = [
  { value: 'all', label: 'All statuses' },
  { value: 'online', label: 'Online' },
  { value: 'offline', label: 'Offline' },
  { value: 'pending', label: 'Pending' },
  { value: 'awaiting', label: 'Awaiting key' },
]

const PAGE_SIZES = [25, 50, 100]

export function HostsPage() {
  const navigate = useNavigate()
  const toast = useToast()
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const canWrite = user?.role === 'admin' || user?.role === 'operator'
  const now = useNow(5000)

  // The search box is intentionally NOT in the URL (it changes per keystroke); the
  // server-side filter is, so a filtered view can be linked.
  const [searchParams, setSearchParams] = useSearchParams()
  const statusFilter = searchParams.get('status') ?? 'all'
  const [search, setSearch] = useState('')
  const [groupFilter, setGroupFilter] = useState<string>('all')
  const [hideStale, setHideStale] = useLocalStorage('tg.hosts.hideStale', false)
  const [columnsOpen, setColumnsOpen] = useState(false)
  const [visibleCols, setVisibleCols] = useLocalStorage<ColumnId[]>(
    'tg.hosts.columns',
    COLUMNS.map((c) => c.id),
  )
  const [sort, setSort] = useState<Sort>({ key: 'name', dir: 'asc' })
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useLocalStorage('tg.hosts.pageSize', 25)

  const [deleteTarget, setDeleteTarget] = useState<Router | null>(null)
  const [rotateTarget, setRotateTarget] = useState<Router | null>(null)
  const [scriptTarget, setScriptTarget] = useState<Router | null>(null)

  const debouncedSearch = useDebounced(search, 250)

  const listQuery = useQuery({
    queryKey: ['routers', { status: statusFilter, q: debouncedSearch }],
    queryFn: ({ signal }) =>
      api.listRouters(
        {
          status: statusFilter === 'all' ? undefined : statusFilter,
          q: debouncedSearch || undefined,
        },
        signal,
      ),
    refetchInterval: 5000,
    // Keep the previous page of rows on screen while a new filter loads.
    placeholderData: (prev) => prev,
  })

  // Client-side group filter + stale hiding + sorting + pagination. At 100+
  // routers this stays far cheaper than a round-trip per interaction.
  const groups = useMemo(() => {
    const set = new Set<string>()
    for (const r of listQuery.data?.items ?? []) if (r.group_name) set.add(r.group_name)
    return Array.from(set).sort((a, b) => a.localeCompare(b))
  }, [listQuery.data])

  const filtered = useMemo(() => {
    let rows = listQuery.data?.items ?? []
    if (groupFilter !== 'all') rows = rows.filter((r) => r.group_name === groupFilter)
    if (hideStale) {
      rows = rows.filter((r) => {
        if (!r.last_heartbeat_at) return r.status === 'pending' || r.status === 'awaiting'
        const age = (now - Date.parse(r.last_heartbeat_at)) / 1000
        return age < 1800
      })
    }
    const dir = sort.dir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      switch (sort.key) {
        case 'status':
          return a.status.localeCompare(b.status) * dir
        case 'lastSeen': {
          const at = a.last_seen_at ? Date.parse(a.last_seen_at) : 0
          const bt = b.last_seen_at ? Date.parse(b.last_seen_at) : 0
          return (at - bt) * dir
        }
        case 'uptime':
          return ((a.uptime_seconds ?? -1) - (b.uptime_seconds ?? -1)) * dir
        default:
          return a.name.localeCompare(b.name, undefined, { numeric: true }) * dir
      }
    })
  }, [listQuery.data, groupFilter, hideStale, sort, now])

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(page, pageCount - 1)
  const pageRows = filtered.slice(safePage * pageSize, safePage * pageSize + pageSize)

  const totals = listQuery.data ?? { total: 0, online: 0, offline: 0, pending: 0 }
  // "pending" from the server already covers both `pending` and `awaiting` routers.
  const needsAttention = totals.offline + totals.pending

  const onSort = useCallback((key: SortKey) => {
    setSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }))
  }, [])

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const toggleAll = useCallback(() => {
    setSelected((prev) => {
      const allSelected = pageRows.length > 0 && pageRows.every((r) => prev.has(r.id))
      if (allSelected) {
        const next = new Set(prev)
        for (const r of pageRows) next.delete(r.id)
        return next
      }
      const next = new Set(prev)
      for (const r of pageRows) next.add(r.id)
      return next
    })
  }, [pageRows])

  const setStatusFilter = (value: string) => {
    setPage(0)
    const next = new URLSearchParams(searchParams)
    if (value === 'all') next.delete('status')
    else next.set('status', value)
    setSearchParams(next, { replace: true })
  }

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['routers'] })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteRouter(id),
    onSuccess: () => {
      toast.success('Router deleted. Its SSH key was revoked and the proxy route removed.')
      setDeleteTarget(null)
      setSelected(new Set())
      void invalidate()
    },
    onError: (err) => toast.error(friendlyMessage(err)),
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.rotateKey(id),
    onSuccess: (data, id) => {
      setRotateTarget(null)
      void invalidate()
      // The new command is shown once - send the operator straight to the wizard's
      // step-3 view instead of a toast that hides the token.
      navigate(`/routers/new?step=3&id=${encodeURIComponent(id)}`, {
        state: { created: { ...data, id } },
      })
    },
    onError: (err) => toast.error(friendlyMessage(err)),
  })

  const consoleMutation = useMutation({
    mutationFn: (id: string) => api.consoleStart(id),
    onSuccess: (_data, id) => {
      navigate(`/routers/${encodeURIComponent(id)}/console`)
    },
    onError: (err) => toast.error(friendlyMessage(err)),
  })

  const openLuCI = (r: Router) => {
    // Through the launch endpoint: it exchanges this panel session for a cookie on the
    // router's own host, which is what stops "Open LuCI" from bouncing round the login page.
    // A refusal is surfaced rather than swallowed - an unusable host (an IP as the subdomain
    // suffix is the usual one) otherwise looks exactly like a dead button.
    const result = openExternal(r.launch_url || r.url)
    if (!result.ok) toast.error(result.reason)
  }

  const selectedCount = selected.size
  const isFiltering = statusFilter !== 'all' || debouncedSearch !== '' || groupFilter !== 'all' || hideStale

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <TopBar search={search} onSearchChange={setSearch}>
        <FleetCounters online={totals.online} offline={totals.offline} pending={totals.pending} />
      </TopBar>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-[1600px] px-4 py-4">
          {/* ------------------------------------------------- header + CTA */}
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-base font-semibold tracking-tight text-text">Hosts</h1>
              <p className="mt-0.5 text-2xs text-muted">
                {pluralize(totals.total, 'router')} behind SSH reverse tunnels
                {totals.total > 0 ? ` · ${Math.round((totals.online / totals.total) * 100)}% online` : ''}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button icon="refresh" size="sm" onClick={() => void listQuery.refetch()} loading={listQuery.isFetching && !listQuery.isLoading}>
                Refresh
              </Button>
              {canWrite ? (
                <Button variant="primary" icon="plus" size="md" onClick={() => navigate('/routers/new')}>
                  Add Router
                </Button>
              ) : null}
            </div>
          </div>

          {/* ------------------------------------------------- KPI row */}
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Kpi
              label="Total Routers"
              value={totals.total}
              hint={`${pluralize(totals.online, 'online')} · ${totals.offline} offline`}
              icon="server"
              tone="accent"
              progress={totals.total ? (totals.online / totals.total) * 100 : 0}
              onClick={() => setStatusFilter('all')}
              active={statusFilter === 'all'}
            />
            <Kpi
              label="Needs Attention"
              value={needsAttention}
              hint={needsAttention === 0 ? 'Everything is healthy' : 'Offline, pending or awaiting key'}
              icon="alert"
              tone={needsAttention > 0 ? 'warning' : 'success'}
              delta={
                needsAttention === 0 ? (
                  <span className="flex items-center gap-1 text-success">
                    <Icon name="check-circle" size={11} /> ok
                  </span>
                ) : undefined
              }
              onClick={() => setStatusFilter('offline')}
              active={statusFilter === 'offline'}
            />
            <Kpi
              label="Connected"
              value={totals.online}
              hint={`${totals.total ? Math.round((totals.online / totals.total) * 100) : 0}% of fleet online`}
              icon="wifi"
              tone="success"
              progress={totals.total ? (totals.online / totals.total) * 100 : 0}
              onClick={() => setStatusFilter('online')}
              active={statusFilter === 'online'}
            />
            <Kpi
              label="Pending Install"
              value={totals.pending}
              hint="Tokens issued, no key exchanged yet"
              icon="clock"
              tone="warning"
              onClick={() => setStatusFilter('pending')}
              active={statusFilter === 'pending'}
            />
          </div>

          {/* ------------------------------------------------- toolbar */}
          <div className="tg-card overflow-hidden">
            <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
              <div className="relative min-w-[180px] flex-1 sm:max-w-xs">
                <Icon
                  name="search"
                  size={13}
                  className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint"
                />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(0)
                  }}
                  placeholder="Name, hostname or IP…"
                  aria-label="Filter hosts by name, hostname or IP"
                  className="h-8 w-full rounded border border-border bg-surface-2 pl-8 pr-2 text-xs text-text placeholder:text-faint focus:border-accent focus:outline-none focus-visible:outline-none"
                />
              </div>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                aria-label="Filter by connection status"
                className="h-8 rounded border border-border bg-surface-2 px-2 text-xs text-text focus:border-accent focus:outline-none"
              >
                {STATUS_FILTERS.map((s) => (
                  <option key={s.value} value={s.value}>
                    {s.label}
                  </option>
                ))}
              </select>

              <select
                value={groupFilter}
                onChange={(e) => {
                  setGroupFilter(e.target.value)
                  setPage(0)
                }}
                aria-label="Filter by group"
                disabled={groups.length === 0}
                className="h-8 max-w-[160px] rounded border border-border bg-surface-2 px-2 text-xs text-text focus:border-accent focus:outline-none disabled:opacity-50"
              >
                <option value="all">All groups</option>
                {groups.map((g) => (
                  <option key={g} value={g}>
                    {g}
                  </option>
                ))}
              </select>

              <button
                type="button"
                onClick={() => setHideStale(!hideStale)}
                aria-pressed={hideStale}
                className={cn(
                  'flex h-8 items-center gap-1.5 rounded border px-2 text-xs transition-colors',
                  hideStale
                    ? 'border-accent/50 bg-accent/10 text-accent'
                    : 'border-border bg-surface-2 text-muted hover:text-text',
                )}
                title="Hide routers whose last heartbeat is older than 30 minutes"
              >
                <Icon name={hideStale ? 'eye-off' : 'eye'} size={12} />
                Hide stale
              </button>

              <div className="relative">
                <button
                  type="button"
                  onClick={() => setColumnsOpen((v) => !v)}
                  aria-haspopup="dialog"
                  aria-expanded={columnsOpen}
                  className="flex h-8 items-center gap-1.5 rounded border border-border bg-surface-2 px-2 text-xs text-muted transition-colors hover:text-text"
                >
                  <Icon name="columns" size={12} />
                  Columns
                </button>
                {columnsOpen ? (
                  <div
                    role="dialog"
                    aria-label="Choose visible columns"
                    className="absolute right-0 top-full z-30 mt-1 w-56 animate-pop-in rounded border border-border bg-surface p-2 shadow-pop"
                  >
                    <div className="mb-1 flex items-center justify-between px-1">
                      <span className="text-2xs uppercase tracking-wide text-muted">Visible columns</span>
                      <button
                        type="button"
                        onClick={() => {
                          setVisibleCols(COLUMNS.map((c) => c.id))
                          setColumnsOpen(false)
                        }}
                        className="text-2xs text-accent hover:underline"
                      >
                        Reset
                      </button>
                    </div>
                    {COLUMNS.map((col) => {
                      const checked = visibleCols.includes(col.id)
                      return (
                        <label
                          key={col.id}
                          className={cn(
                            'flex cursor-pointer items-center gap-2 rounded-sm px-1.5 py-1 text-xs',
                            col.always ? 'cursor-not-allowed opacity-60' : 'hover:bg-surface-2',
                          )}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={col.always}
                            onChange={() => {
                              setVisibleCols(
                                checked ? visibleCols.filter((c) => c !== col.id) : [...visibleCols, col.id],
                              )
                            }}
                            className="h-3 w-3 accent-[rgb(var(--tg-accent))]"
                          />
                          <span className="text-text">{col.label}</span>
                          {col.always ? <span className="ml-auto text-3xs text-faint">always</span> : null}
                        </label>
                      )
                    })}
                  </div>
                ) : null}
              </div>

              <div className="ml-auto flex items-center gap-2">
                {selectedCount > 0 ? (
                  <span className="text-2xs text-muted">
                    {selectedCount} selected
                  </span>
                ) : null}
                {isFiltering ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    icon="x"
                    onClick={() => {
                      setSearch('')
                      setGroupFilter('all')
                      setHideStale(false)
                      setStatusFilter('all')
                    }}
                  >
                    Clear
                  </Button>
                ) : null}
              </div>
            </div>

            {/* ------------------------------------------------- table */}
            {listQuery.isLoading ? (
              <TableSkeleton rows={8} cols={8} />
            ) : listQuery.isError ? (
              <ErrorState error={listQuery.error} onRetry={() => void listQuery.refetch()} />
            ) : pageRows.length === 0 ? (
              <EmptyState
                icon={isFiltering ? 'filter' : 'server'}
                title={isFiltering ? 'No routers match these filters' : 'No routers yet'}
                description={
                  isFiltering
                    ? 'Adjust or clear the filters to see the rest of the fleet.'
                    : 'Add your first router to generate a one-line install command. The router dials out, so it works behind NAT without a static IP.'
                }
                action={
                  isFiltering ? (
                    <Button
                      size="sm"
                      icon="x"
                      onClick={() => {
                        setSearch('')
                        setGroupFilter('all')
                        setHideStale(false)
                        setStatusFilter('all')
                      }}
                    >
                      Clear filters
                    </Button>
                  ) : canWrite ? (
                    <Button variant="primary" size="sm" icon="plus" onClick={() => navigate('/routers/new')}>
                      Add Router
                    </Button>
                  ) : null
                }
              />
            ) : (
              <HostsTable
                routers={pageRows}
                visible={new Set(visibleCols)}
                sort={sort}
                onSort={onSort}
                selected={selected}
                onToggleSelect={toggleSelect}
                onToggleAll={toggleAll}
                onOpen={(r) => navigate(`/routers/${encodeURIComponent(r.id)}`)}
                onOpenLuCI={openLuCI}
                onConsole={(r) => consoleMutation.mutate(r.id)}
                onShowScript={(r) => setScriptTarget(r)}
                onRotate={(r) => setRotateTarget(r)}
                onDelete={(r) => setDeleteTarget(r)}
                canWrite={canWrite}
              />
            )}

            {/* ------------------------------------------------- footer */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-3 py-2">
              <div className="flex items-center gap-2 text-2xs text-muted">
                <span>Rows per page</span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value))
                    setPage(0)
                  }}
                  aria-label="Rows per page"
                  className="h-7 rounded border border-border bg-surface-2 px-1.5 text-2xs text-text focus:border-accent focus:outline-none"
                >
                  {PAGE_SIZES.map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
                <span className="tabular-nums">
                  {filtered.length === 0
                    ? '0'
                    : `${safePage * pageSize + 1}–${Math.min(filtered.length, (safePage + 1) * pageSize)}`}{' '}
                  of {filtered.length}
                </span>
                {listQuery.data && listQuery.data.total !== filtered.length ? (
                  <span className="text-faint">({listQuery.data.total} total before local filters)</span>
                ) : null}
              </div>

              <div className="flex items-center gap-1">
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="First page"
                  disabled={safePage === 0}
                  onClick={() => setPage(0)}
                  className="h-7 w-7"
                >
                  <Icon name="chevron-left" size={13} />
                  <Icon name="chevron-left" size={13} className="-ml-1.5" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="Previous page"
                  disabled={safePage === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  className="h-7 w-7"
                >
                  <Icon name="chevron-left" size={13} />
                </Button>
                <span className="px-1.5 text-2xs tabular-nums text-muted">
                  {safePage + 1} / {pageCount}
                </span>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="Next page"
                  disabled={safePage >= pageCount - 1}
                  onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                  className="h-7 w-7"
                >
                  <Icon name="chevron-right" size={13} />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label="Last page"
                  disabled={safePage >= pageCount - 1}
                  onClick={() => setPage(pageCount - 1)}
                  className="h-7 w-7"
                >
                  <Icon name="chevron-right" size={13} />
                  <Icon name="chevron-right" size={13} className="-ml-1.5" />
                </Button>
              </div>
            </div>
          </div>

          {listQuery.isFetching && !listQuery.isLoading ? (
            <p className="mt-2 flex items-center gap-1.5 text-3xs text-faint" aria-live="polite">
              <Icon name="spinner" size={10} className="animate-spin" /> refreshing every 5s
            </p>
          ) : (
            <p className="mt-2 text-3xs text-faint">Auto-refresh every 5 seconds</p>
          )}
        </div>
      </div>

      {/* ------------------------------------------------- dialogs */}
      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
        title={`Delete ${deleteTarget?.name ?? 'router'}?`}
        description="This revokes the SSH key, removes the proxy route and deletes the router's history. The router keeps retrying its tunnel until it is reinstalled or stopped."
        confirmLabel="Delete router"
        destructive
        loading={deleteMutation.isPending}
      />

      <ConfirmDialog
        open={rotateTarget !== null}
        onClose={() => setRotateTarget(null)}
        onConfirm={() => rotateTarget && rotateMutation.mutate(rotateTarget.id)}
        title={`Rotate the key for ${rotateTarget?.name ?? 'router'}?`}
        description="The current key stops working immediately. A new one-line install command is generated and shown once - the router re-registers when you run it."
        confirmLabel="Rotate key"
        loading={rotateMutation.isPending}
      />

      <ScriptDialog
        router={scriptTarget}
        onClose={() => setScriptTarget(null)}
        onInstall={(id) => navigate(`/routers/new?step=3&id=${encodeURIComponent(id)}`)}
      />
    </div>
  )
}

/**
 * "Show install script" - re-fetches the current script. The plaintext bootstrap
 * token is only minted on create/rotate, so if the token expired this dialog says
 * so and offers rotation rather than pretending a command exists.
 */
function ScriptDialog({
  router,
  onClose,
  onInstall,
}: {
  router: Router | null
  onClose: () => void
  onInstall: (id: string) => void
}) {
  const toast = useToast()
  const scriptQuery = useQuery({
    queryKey: ['router-script', router?.id],
    queryFn: ({ signal }) => api.installScript(router!.id, signal),
    enabled: router !== null,
    retry: false,
  })

  return (
    <Modal
      open={router !== null}
      onClose={onClose}
      title={`Install script - ${router?.name ?? ''}`}
      description="The command embeds a single-use bootstrap token. Run it on the router; the token is consumed on the first successful exchange."
      size="lg"
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" icon="terminal" onClick={() => router && onInstall(router.id)}>
            Open install wizard
          </Button>
        </>
      }
    >
      {scriptQuery.isLoading ? (
        <div className="py-6 text-center text-xs text-muted">Loading…</div>
      ) : scriptQuery.isError ? (
        <InlineAlert tone="warning" title="No active install command">
          {friendlyMessage(scriptQuery.error)} Rotate the key to mint a fresh single-use token.
        </InlineAlert>
      ) : scriptQuery.data ? (
        <div>
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="text-3xs text-faint">
              Multi-line: run the whole block, not just the first line.
            </span>
            <Button
              size="sm"
              variant="secondary"
              icon="copy"
              onClick={async () => {
                // The served string verbatim, newlines included - a command with a line dropped
                // is a command that does something else.
                const ok = await copyText(scriptQuery.data?.install_command ?? '')
                if (ok) toast.success('Command copied.')
                else toast.error('Clipboard unavailable - select and copy manually.')
              }}
            >
              Copy
            </Button>
          </div>
          <pre className="max-h-64 overflow-auto rounded border border-border bg-bg p-3 font-mono text-2xs leading-relaxed text-text">
            <code>{scriptQuery.data.install_command}</code>
          </pre>
          <p className="mt-2 text-2xs leading-relaxed text-muted">
            Expires{' '}
            {scriptQuery.data.bootstrap_expires_at
              ? new Date(scriptQuery.data.bootstrap_expires_at).toLocaleString()
              : '—'}
            . The token is in the URL, so it stays in the router&apos;s shell history - it is
            single-use, so it only ever buys one install.
          </p>
        </div>
      ) : null}
    </Modal>
  )
}