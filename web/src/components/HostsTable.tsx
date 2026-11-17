import { useMemo } from 'react'
import type { Router } from '../lib/types'
import { cn } from '../lib/cn'
import { formatMac, relativeTime, shortFingerprint, uptime } from '../lib/format'
import { Badge, StatusPill, pillStateFor } from './Badge'
import { ActionMenu } from './Menu'
import type { MenuItem } from './Menu'
import { Icon } from './Icon'

export type ColumnId =
  | 'name'
  | 'hostname'
  | 'group'
  | 'os'
  | 'version'
  | 'status'
  | 'integrations'
  | 'reporting'
  | 'uptime'
  | 'lastSeen'

export const COLUMNS: Array<{ id: ColumnId; label: string; always?: boolean; width?: string }> = [
  { id: 'name', label: 'Friendly Name', always: true },
  { id: 'hostname', label: 'System Hostname' },
  { id: 'group', label: 'Group' },
  { id: 'os', label: 'OS' },
  { id: 'version', label: 'Agent' },
  { id: 'status', label: 'Connection', always: true },
  { id: 'integrations', label: 'Integrations' },
  { id: 'reporting', label: 'Reporting' },
  { id: 'uptime', label: 'Uptime' },
  { id: 'lastSeen', label: 'Last Seen' },
]

export type SortKey = 'name' | 'status' | 'lastSeen' | 'uptime'

export interface Sort {
  key: SortKey
  dir: 'asc' | 'desc'
}

/** Freshness of the heartbeat, which is what "Reporting" actually means. */
function reportingState(r: Router): { label: string; cls: string; bar: number } {
  if (!r.last_heartbeat_at) return { label: 'Never', cls: 'text-faint', bar: 0 }
  const age = (Date.now() - Date.parse(r.last_heartbeat_at)) / 1000
  if (Number.isNaN(age)) return { label: 'Unknown', cls: 'text-faint', bar: 0 }
  if (age < 60) return { label: 'Live', cls: 'text-success', bar: 100 }
  if (age < 300) return { label: 'Recent', cls: 'text-success/70', bar: 66 }
  if (age < 1800) return { label: 'Lagging', cls: 'text-warning', bar: 33 }
  return { label: 'Stale', cls: 'text-danger', bar: 10 }
}

const OS_LABEL: Record<string, string> = { linux: 'Linux', freebsd: 'FreeBSD', windows: 'Windows' }
const OS_ICON = { linux: 'linux', freebsd: 'freebsd', windows: 'windows' } as const

interface Props {
  routers: Router[]
  visible: Set<ColumnId>
  sort: Sort
  onSort: (key: SortKey) => void
  selected: Set<string>
  onToggleSelect: (id: string) => void
  onToggleAll: () => void
  onOpen: (r: Router) => void
  onOpenLuCI: (r: Router) => void
  onConsole: (r: Router) => void
  onShowScript: (r: Router) => void
  onRotate: (r: Router) => void
  onDelete: (r: Router) => void
  canWrite: boolean
}

export function HostsTable({
  routers,
  visible,
  sort,
  onSort,
  selected,
  onToggleSelect,
  onToggleAll,
  onOpen,
  onOpenLuCI,
  onConsole,
  onShowScript,
  onRotate,
  onDelete,
  canWrite,
}: Props) {
  const allSelected = routers.length > 0 && routers.every((r) => selected.has(r.id))
  const someSelected = routers.some((r) => selected.has(r.id))

  const sortIndicator = (key: SortKey) => {
    if (sort.key !== key) return null
    return (
      <Icon
        name="chevron-down"
        size={12}
        className={cn('ml-1 inline-block text-accent transition-transform', sort.dir === 'asc' && 'rotate-180')}
      />
    )
  }

  const ariaSort = (key: SortKey): 'ascending' | 'descending' | 'none' => {
    if (sort.key !== key) return 'none'
    return sort.dir === 'asc' ? 'ascending' : 'descending'
  }

  const SortableTh = ({ key, children, className }: { key: SortKey; children: React.ReactNode; className?: string }) => (
    <th
      scope="col"
      aria-sort={ariaSort(key)}
      className={cn('whitespace-nowrap px-3 py-2 text-left font-medium', className)}
    >
      <button
        type="button"
        onClick={() => onSort(key)}
        className="inline-flex items-center rounded text-2xs uppercase tracking-wide text-muted transition-colors hover:text-text"
      >
        {children}
        {sortIndicator(key)}
      </button>
    </th>
  )

  const menuFor = (r: Router): MenuItem[] => [
    {
      label: 'Open LuCI',
      icon: 'external',
      disabled: !r.url || !r.online,
      disabledReason: !r.url
        ? 'No public URL yet - the proxy route is created once the tunnel is up.'
        : 'The router is offline, so its LuCI page is unreachable.',
      onSelect: () => onOpenLuCI(r),
    },
    {
      label: 'Console',
      icon: 'terminal',
      disabled: !r.console_ready || r.status !== 'online',
      disabledReason: !r.console_ready
        ? 'Console key not installed yet - the router installs it on its next heartbeat.'
        : 'The router is offline, so no shell can be opened.',
      onSelect: () => onConsole(r),
    },
    { label: 'Show install script', icon: 'download', onSelect: () => onShowScript(r), separatorBefore: true },
    { label: 'Rotate key', icon: 'key', onSelect: () => onRotate(r), disabled: !canWrite },
    { label: 'Delete', icon: 'trash', danger: true, onSelect: () => onDelete(r), disabled: !canWrite, separatorBefore: true },
  ]

  return (
    <div className="min-w-0 overflow-x-auto">
      <table className="w-full min-w-[1080px] border-collapse text-left">
        <caption className="sr-only">
          Routers. Use the column headers to sort; open the row menu for actions.
        </caption>
        <thead className="sticky top-0 z-10 bg-surface/95 backdrop-blur">
          <tr className="border-b border-border">
            <th scope="col" className="w-9 px-3 py-2">
              <input
                type="checkbox"
                aria-label={allSelected ? 'Deselect all routers' : 'Select all routers'}
                checked={allSelected}
                ref={(el) => {
                  if (el) el.indeterminate = !allSelected && someSelected
                }}
                onChange={onToggleAll}
                className="h-3.5 w-3.5 cursor-pointer rounded-sm border-border-strong bg-surface-2 accent-[rgb(var(--tg-accent))]"
              />
            </th>

            {visible.has('name') ? (
              <SortableTh key="name" className="min-w-[200px]">
                Friendly Name
              </SortableTh>
            ) : null}
            {visible.has('hostname') ? <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">System Hostname</th> : null}
            {visible.has('group') ? <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">Group</th> : null}
            {visible.has('os') ? <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">OS</th> : null}
            {visible.has('version') ? <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">Agent</th> : null}
            {visible.has('status') ? (
              <SortableTh key="status" className="w-[120px]">
                Connection
              </SortableTh>
            ) : null}
            {visible.has('integrations') ? <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">Integrations</th> : null}
            {visible.has('reporting') ? <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">Reporting</th> : null}
            {visible.has('uptime') ? (
              <SortableTh key="uptime">Uptime</SortableTh>
            ) : null}
            {visible.has('lastSeen') ? (
              <SortableTh key="lastSeen">Last Seen</SortableTh>
            ) : null}
            <th scope="col" className="w-10 px-2 py-2">
              <span className="sr-only">Row actions</span>
            </th>
          </tr>
        </thead>

        <tbody>
          {routers.map((r) => {
            const isSelected = selected.has(r.id)
            const reporting = reportingState(r)
            return (
              <tr
                key={r.id}
                className={cn(
                  'group border-b border-border/60 transition-colors last:border-0',
                  isSelected ? 'bg-accent/[0.06]' : 'hover:bg-surface-2/60',
                )}
              >
                <td className="px-3 py-2.5">
                  <input
                    type="checkbox"
                    aria-label={`Select ${r.name}`}
                    checked={isSelected}
                    onChange={() => onToggleSelect(r.id)}
                    className="h-3.5 w-3.5 cursor-pointer rounded-sm border-border-strong bg-surface-2 accent-[rgb(var(--tg-accent))]"
                  />
                </td>

                {visible.has('name') ? (
                  <td className="px-3 py-2.5">
                    <button
                      type="button"
                      onClick={() => onOpen(r)}
                      className="flex max-w-[260px] flex-col items-start text-left"
                    >
                      <span className="flex items-center gap-1.5 truncate text-xs font-medium text-text group-hover:text-accent">
                        {r.name}
                        {!r.has_key ? (
                          <Icon name="key" size={11} className="shrink-0 text-warning" aria-label="No key installed" />
                        ) : null}
                      </span>
                      <span className="truncate font-mono text-3xs text-faint">{r.slug}</span>
                    </button>
                  </td>
                ) : null}

                {visible.has('hostname') ? (
                  <td className="px-3 py-2.5">
                    <span className="block max-w-[180px] truncate font-mono text-2xs text-muted">
                      {r.hostname ?? <span className="text-faint">—</span>}
                    </span>
                    {r.client_ip ? (
                      <span className="block font-mono text-3xs text-faint">{r.client_ip}</span>
                    ) : null}
                  </td>
                ) : null}

                {visible.has('group') ? (
                  <td className="px-3 py-2.5">
                    {r.group_name ? (
                      <Badge tone="accent">{r.group_name}</Badge>
                    ) : (
                      <span className="text-2xs text-faint">ungrouped</span>
                    )}
                  </td>
                ) : null}

                {visible.has('os') ? (
                  <td className="px-3 py-2.5">
                    <span className="flex items-center gap-1.5 text-2xs text-muted">
                      <Icon name={OS_ICON[r.os_type as keyof typeof OS_ICON] ?? 'server'} size={12} className="text-faint" />
                      {OS_LABEL[r.os_type] ?? r.os_type}
                    </span>
                    {r.openwrt_version ? (
                      <span className="mt-0.5 block truncate text-3xs text-faint" title={r.openwrt_version}>
                        {r.openwrt_version}
                      </span>
                    ) : null}
                  </td>
                ) : null}

                {visible.has('version') ? (
                  <td className="px-3 py-2.5">
                    <span className="font-mono text-2xs text-muted">{r.client_version ?? '—'}</span>
                  </td>
                ) : null}

                {visible.has('status') ? (
                  <td className="px-3 py-2.5">
                    <StatusPill state={pillStateFor(r.status)} />
                    {r.status === 'online' && !r.health_ok ? (
                      <span className="mt-1 flex items-center gap-1 text-3xs text-warning" title="Tunnel is up but LuCI health check failed">
                        <Icon name="alert" size={10} />
                        health failing
                      </span>
                    ) : null}
                  </td>
                ) : null}

                {visible.has('integrations') ? (
                  <td className="px-3 py-2.5">
                    {r.integrations.length === 0 ? (
                      <span className="text-2xs text-faint">—</span>
                    ) : (
                      <span className="flex max-w-[180px] flex-wrap gap-1">
                        {r.integrations.slice(0, 2).map((it) => (
                          <Badge key={it} mono>
                            {it}
                          </Badge>
                        ))}
                        {r.integrations.length > 2 ? (
                          <Badge tone="neutral" title={r.integrations.join(', ')}>
                            +{r.integrations.length - 2}
                          </Badge>
                        ) : null}
                      </span>
                    )}
                  </td>
                ) : null}

                {visible.has('reporting') ? (
                  <td className="px-3 py-2.5">
                    <span className={cn('flex items-center gap-1.5 text-2xs', reporting.cls)}>
                      <span className="h-1 w-8 overflow-hidden rounded-full bg-surface-3" aria-hidden="true">
                        <span
                          className="block h-full rounded-full bg-current"
                          style={{ width: `${reporting.bar}%` }}
                        />
                      </span>
                      {reporting.label}
                    </span>
                    <span className="mt-0.5 block text-3xs text-faint">
                      {r.last_heartbeat_at ? relativeTime(r.last_heartbeat_at) : 'no heartbeat'}
                    </span>
                  </td>
                ) : null}

                {visible.has('uptime') ? (
                  <td className="px-3 py-2.5">
                    <span className="font-mono text-2xs text-muted">{uptime(r.uptime_seconds)}</span>
                  </td>
                ) : null}

                {visible.has('lastSeen') ? (
                  <td className="px-3 py-2.5">
                    <span
                      className="text-2xs text-muted"
                      title={r.last_seen_at ? new Date(r.last_seen_at).toLocaleString() : 'never'}
                    >
                      {relativeTime(r.last_seen_at)}
                    </span>
                  </td>
                ) : null}

                <td className="px-2 py-2.5 text-right">
                  <ActionMenu items={menuFor(r)} label={`Actions for ${r.name}`} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** Small reusable fingerprint cell used by the detail page. */
export function Fingerprint({ value }: { value: string | null }) {
  const short = useMemo(() => shortFingerprint(value), [value])
  return (
    <span className="font-mono text-2xs text-muted" title={value ?? undefined}>
      {short}
    </span>
  )
}

export { formatMac }
