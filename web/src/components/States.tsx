import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { friendlyMessage } from '../lib/api'
import { Button } from './Button'
import { Icon } from './Icon'
import type { IconName } from './Icon'

/** Shimmer placeholder with the same box model as the real row, so nothing jumps. */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={cn(
        'animate-shimmer rounded-sm bg-surface-3/70',
        'bg-[linear-gradient(90deg,rgb(var(--tg-surface-3)/0.5),rgb(var(--tg-surface-3)/1),rgb(var(--tg-surface-3)/0.5))]',
        '[background-size:400px_100%]',
        className,
      )}
    />
  )
}

export function TableSkeleton({ rows = 8, cols = 8 }: { rows?: number; cols?: number }) {
  return (
    <div aria-busy="true" aria-live="polite" aria-label="Loading routers">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex items-center gap-4 border-b border-border/60 px-4 py-3 last:border-0">
          {Array.from({ length: cols }).map((__, c) => (
            <Skeleton
              key={c}
              className={cn('h-3.5', c === 0 ? 'w-4' : c === 1 ? 'w-40' : c === 2 ? 'w-28' : 'w-20')}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

export function EmptyState({
  icon = 'server',
  title,
  description,
  action,
}: {
  icon?: IconName
  title: string
  description?: ReactNode
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-lg border border-border bg-surface-2 text-muted">
        <Icon name={icon} size={20} />
      </div>
      <h3 className="text-sm font-medium text-text">{title}</h3>
      {description ? <p className="mt-1.5 max-w-sm text-xs leading-relaxed text-muted">{description}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center" role="alert">
      <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-lg border border-danger/30 bg-danger/10 text-danger">
        <Icon name="alert" size={20} />
      </div>
      <h3 className="text-sm font-medium text-text">Could not load data</h3>
      <p className="mt-1.5 max-w-md text-xs leading-relaxed text-muted">{friendlyMessage(error)}</p>
      {onRetry ? (
        <Button className="mt-4" icon="refresh" onClick={onRetry} size="sm">
          Try again
        </Button>
      ) : null}
    </div>
  )
}

/** Inline banner for form/section level failures (does not replace the whole screen). */
export function InlineAlert({
  tone = 'danger',
  title,
  children,
  action,
  className,
}: {
  tone?: 'danger' | 'warning' | 'info' | 'success'
  title?: string
  children?: ReactNode
  action?: ReactNode
  className?: string
}) {
  const map = {
    danger: 'border-danger/35 bg-danger/[0.07] text-danger',
    warning: 'border-warning/35 bg-warning/[0.07] text-warning',
    info: 'border-accent/35 bg-accent/[0.07] text-accent',
    success: 'border-success/35 bg-success/[0.07] text-success',
  } as const
  const icons: Record<string, IconName> = {
    danger: 'alert',
    warning: 'alert',
    info: 'info',
    success: 'check-circle',
  }
  return (
    <div
      className={cn('flex items-start gap-2.5 rounded border px-3 py-2.5 text-xs', map[tone], className)}
      role={tone === 'danger' ? 'alert' : 'status'}
    >
      <Icon name={icons[tone]!} size={14} className="mt-px shrink-0" />
      <div className="min-w-0 flex-1">
        {title ? <div className="font-medium">{title}</div> : null}
        {children ? <div className={cn('leading-relaxed', title && 'mt-0.5 text-muted')}>{children}</div> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  )
}

/** Spinner with an accessible label for buttons/panels. */
export function Spinner({ label = 'Loading', size = 16 }: { label?: string; size?: number }) {
  return (
    <span role="status" aria-live="polite" className="inline-flex items-center gap-2">
      <Icon name="spinner" size={size} className="animate-spin text-muted" />
      <span className="sr-only">{label}</span>
    </span>
  )
}

/** Small labelled metric used in the top bar and detail headers. */
export function Stat({
  label,
  value,
  tone = 'text-text',
  hint,
}: {
  label: string
  value: ReactNode
  tone?: string
  hint?: string
}) {
  return (
    <div className="flex items-baseline gap-1.5" title={hint}>
      <span className="text-2xs uppercase tracking-wide text-muted">{label}</span>
      <span className={cn('text-xs font-semibold tabular-nums', tone)}>{value}</span>
    </div>
  )
}
