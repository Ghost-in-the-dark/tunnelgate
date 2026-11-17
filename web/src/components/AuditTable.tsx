import { relativeTime, absoluteTime } from '../lib/format'
import type { AuditEntry } from '../lib/types'
import { cn } from '../lib/cn'
import { Badge } from './Badge'
import { Icon } from './Icon'
import { Skeleton } from './States'

type Tone = 'success' | 'warning' | 'danger' | 'neutral' | 'accent'

/** Outcomes are free-form strings on the wire; map the common ones and stay neutral otherwise. */
function outcomeTone(outcome: string): Tone {
  const o = outcome.toLowerCase()
  if (o === 'ok' || o === 'success' || o === 'allowed') return 'success'
  if (o === 'denied' || o === 'forbidden' || o === 'rejected') return 'warning'
  if (o === 'error' || o === 'failed' || o === 'failure') return 'danger'
  return 'neutral'
}

/** Detail strings are JSON-ish and long; keep one line with the full value on hover. */
function DetailCell({ detail }: { detail: string | null }) {
  if (!detail) return <span className="text-faint">—</span>
  return (
    <span className="block max-w-[360px] truncate font-mono text-3xs text-muted" title={detail}>
      {detail}
    </span>
  )
}

export function AuditTable({
  entries,
  loading,
  showRouter = true,
  onRouterClick,
}: {
  entries: AuditEntry[]
  loading?: boolean
  showRouter?: boolean
  onRouterClick?: (id: string) => void
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px] border-collapse text-left">
        <caption className="sr-only">Audit trail, newest first</caption>
        <thead className="bg-surface/95">
          <tr className="border-b border-border">
            <th scope="col" className="w-[132px] px-3 py-2 text-2xs uppercase tracking-wide text-muted">
              When
            </th>
            <th scope="col" className="w-[130px] px-3 py-2 text-2xs uppercase tracking-wide text-muted">
              Actor
            </th>
            <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">
              Action
            </th>
            <th scope="col" className="w-[96px] px-3 py-2 text-2xs uppercase tracking-wide text-muted">
              Outcome
            </th>
            {showRouter ? (
              <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">
                Router
              </th>
            ) : null}
            <th scope="col" className="w-[120px] px-3 py-2 text-2xs uppercase tracking-wide text-muted">
              Source IP
            </th>
            <th scope="col" className="px-3 py-2 text-2xs uppercase tracking-wide text-muted">
              Detail
            </th>
          </tr>
        </thead>
        <tbody>
          {loading
            ? Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="border-b border-border/60">
                  {Array.from({ length: showRouter ? 7 : 6 }).map((__, c) => (
                    <td key={c} className="px-3 py-2.5">
                      <Skeleton className="h-3 w-20" />
                    </td>
                  ))}
                </tr>
              ))
            : entries.map((e) => (
                <tr key={e.id} className="border-b border-border/60 transition-colors last:border-0 hover:bg-surface-2/50">
                  <td className="whitespace-nowrap px-3 py-2">
                    <span className="text-2xs text-text" title={e.ts ? absoluteTime(e.ts) : 'unknown time'}>
                      {relativeTime(e.ts)}
                    </span>
                    <span className="mt-0.5 block font-mono text-3xs text-faint">
                      {e.ts ? new Date(e.ts).toLocaleTimeString() : '—'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    {e.actor_username ? (
                      <span className="flex items-center gap-1.5 text-2xs text-text">
                        <Icon name="user" size={11} className="text-faint" />
                        {e.actor_username}
                      </span>
                    ) : (
                      <span className="text-2xs text-faint">system</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-2xs text-text">{e.action}</span>
                  </td>
                  <td className="px-3 py-2">
                    <Badge tone={outcomeTone(e.outcome)} mono>
                      {e.outcome}
                    </Badge>
                  </td>
                  {showRouter ? (
                    <td className="px-3 py-2">
                      {e.router_name || e.router_id ? (
                        onRouterClick && e.router_id ? (
                          <button
                            type="button"
                            onClick={() => onRouterClick(e.router_id!)}
                            className={cn('max-w-[180px] truncate text-left text-2xs text-accent hover:underline')}
                          >
                            {e.router_name ?? e.router_id.slice(0, 8)}
                          </button>
                        ) : (
                          <span className="text-2xs text-muted">{e.router_name ?? '—'}</span>
                        )
                      ) : (
                        <span className="text-2xs text-faint">—</span>
                      )}
                    </td>
                  ) : null}
                  <td className="px-3 py-2">
                    <span className="font-mono text-3xs text-muted">{e.ip ?? '—'}</span>
                  </td>
                  <td className="px-3 py-2">
                    <DetailCell detail={e.detail} />
                  </td>
                </tr>
              ))}
        </tbody>
      </table>
    </div>
  )
}
