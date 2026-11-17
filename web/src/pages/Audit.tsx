import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useDebounced } from '../lib/hooks'
import { pluralize } from '../lib/format'
import { AuditTable } from '../components/AuditTable'
import { TopBar } from '../components/AppShell'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { EmptyState, ErrorState, InlineAlert } from '../components/States'
import { TextField, SelectField } from '../components/Field'
import { useToast } from '../components/Toast'

const PAGE_SIZE = 50

export function AuditPage() {
  const navigate = useNavigate()
  const toast = useToast()

  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const [offset, setOffset] = useState(0)

  const debouncedActor = useDebounced(actor.trim(), 300)
  const debouncedAction = useDebounced(action.trim(), 300)

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ['audit', debouncedActor, debouncedAction, outcome, offset],
    queryFn: ({ signal }) =>
      api.listAudit(
        {
          actor: debouncedActor || undefined,
          action: debouncedAction || undefined,
          limit: PAGE_SIZE,
          offset,
        },
        signal,
      ),
    placeholderData: keepPreviousData,
    refetchInterval: 15_000,
  })

  // Outcome filtering is done client-side: the wire contract only filters by router/actor/action.
  const rows = useMemo(() => {
    const items = data?.items ?? []
    return outcome ? items.filter((e) => e.outcome.toLowerCase() === outcome) : items
  }, [data, outcome])

  const total = data?.total ?? 0
  const page = Math.floor(offset / PAGE_SIZE) + 1
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const filtersActive = Boolean(debouncedActor || debouncedAction || outcome)

  const clearFilters = () => {
    setActor('')
    setAction('')
    setOutcome('')
    setOffset(0)
  }

  const exportCsv = () => {
    const items = data?.items ?? []
    if (items.length === 0) {
      toast.info('Nothing to export on this page.')
      return
    }
    const header = ['ts', 'actor', 'action', 'outcome', 'router', 'ip', 'detail']
    const escape = (v: unknown) => {
      const s = v === null || v === undefined ? '' : String(v)
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
    }
    const csv = [
      header.join(','),
      ...items.map((e) =>
        [e.ts, e.actor_username, e.action, e.outcome, e.router_name ?? e.router_id, e.ip, e.detail]
          .map(escape)
          .join(','),
      ),
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `tunnelgate-audit-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
    toast.success(`Exported ${items.length} ${pluralize(items.length, 'entry', 'entries')} from this page.`)
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar search={action} onSearchChange={(v) => { setAction(v); setOffset(0) }} placeholder="Filter by action…">
        <Button size="sm" variant="secondary" icon="download" onClick={exportCsv} disabled={rows.length === 0}>
          Export CSV
        </Button>
      </TopBar>

      <div className="flex min-h-0 flex-1 flex-col">
        <header className="flex flex-wrap items-end justify-between gap-3 px-4 pb-3 pt-4">
          <div>
            <h1 className="text-base font-semibold text-text">Audit</h1>
            <p className="mt-0.5 text-2xs text-muted">
              Every privileged action on the panel: sign-ins, key rotations, console sessions, deletions.
              {total > 0 ? <> {pluralize(total, 'entry', 'entries')} total.</> : null}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {isFetching && !isLoading ? (
              <span className="flex items-center gap-1.5 text-3xs text-faint">
                <Icon name="spinner" size={11} className="animate-spin" />
                refreshing
              </span>
            ) : null}
            <Button size="sm" variant="secondary" icon="refresh" onClick={() => void refetch()}>
              Refresh
            </Button>
          </div>
        </header>

        <div className="flex flex-wrap items-end gap-3 border-y border-border bg-surface/40 px-4 py-2.5">
          <TextField
            label="Actor"
            name="actor"
            value={actor}
            onChange={(e) => {
              setActor(e.target.value)
              setOffset(0)
            }}
            placeholder="username"
            className="w-40"
          />
          <TextField
            label="Action"
            name="action"
            value={action}
            onChange={(e) => {
              setAction(e.target.value)
              setOffset(0)
            }}
            placeholder="router.rotate_key"
            className="w-56"
          />
          <SelectField
            label="Outcome"
            name="outcome"
            value={outcome}
            onChange={(e) => {
              setOutcome(e.target.value)
              setOffset(0)
            }}
            className="w-36"
            options={[
              { value: '', label: 'Any' },
              { value: 'ok', label: 'ok' },
              { value: 'denied', label: 'denied' },
              { value: 'error', label: 'error' },
            ]}
          />
          {filtersActive ? (
            <Button size="sm" variant="ghost" icon="x" onClick={clearFilters}>
              Clear
            </Button>
          ) : null}
          <span className="ml-auto self-center text-3xs text-faint">
            newest first · refreshes every 15s
          </span>
        </div>

        <div className="min-h-0 flex-1 overflow-auto">
          {error ? (
            <ErrorState error={error} onRetry={() => void refetch()} />
          ) : !isLoading && rows.length === 0 ? (
            <EmptyState
              icon="audit"
              title={filtersActive ? 'No entries match these filters' : 'No audit entries yet'}
              description={
                filtersActive ? (
                  'Try a shorter action fragment, or clear the filters to see everything.'
                ) : (
                  'Sign in, rotate a key or open a console and the action shows up here within seconds.'
                )
              }
              action={
                filtersActive ? (
                  <Button size="sm" icon="x" onClick={clearFilters}>
                    Clear filters
                  </Button>
                ) : null
              }
            />
          ) : (
            <>
              {outcome ? (
                <div className="px-4 pt-3">
                  <InlineAlert tone="info" title="Outcome filter is applied to this page only">
                    The API filters by router, actor and action. For an exact outcome filter, narrow the
                    time range with the other controls.
                  </InlineAlert>
                </div>
              ) : null}
              <AuditTable
                entries={rows}
                loading={isLoading}
                onRouterClick={(id) => navigate(`/routers/${encodeURIComponent(id)}`)}
              />
            </>
          )}
        </div>

        <footer className="flex items-center justify-between border-t border-border bg-surface/40 px-4 py-2 text-2xs text-muted">
          <span>
            Page {page} of {pages} · {total} {pluralize(total, 'entry', 'entries')}
          </span>
          <div className="flex items-center gap-1">
            <Button
              size="sm"
              variant="ghost"
              icon="chevron-left"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              Prev
            </Button>
            <Button
              size="sm"
              variant="ghost"
              iconRight="chevron-right"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              Next
            </Button>
          </div>
        </footer>
      </div>
    </div>
  )
}
