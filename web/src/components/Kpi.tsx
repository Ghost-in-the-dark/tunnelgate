import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Icon } from './Icon'
import type { IconName } from './Icon'

export interface KpiProps {
  label: string
  value: ReactNode
  /** Secondary line, e.g. "of 128 total" or "12% of fleet". */
  hint?: ReactNode
  icon: IconName
  tone?: 'accent' | 'success' | 'warning' | 'danger' | 'neutral'
  /** 0..100 - drives the thin progress rail under the value. */
  progress?: number
  onClick?: () => void
  active?: boolean
  /** Extra context rendered as a live change indicator. */
  delta?: ReactNode
}

const TONE: Record<NonNullable<KpiProps['tone']>, { icon: string; text: string; bar: string }> = {
  accent: { icon: 'bg-accent/12 text-accent border-accent/25', text: 'text-text', bar: 'bg-accent' },
  success: { icon: 'bg-success/12 text-success border-success/25', text: 'text-text', bar: 'bg-success' },
  warning: { icon: 'bg-warning/12 text-warning border-warning/25', text: 'text-text', bar: 'bg-warning' },
  danger: { icon: 'bg-danger/12 text-danger border-danger/25', text: 'text-text', bar: 'bg-danger' },
  neutral: { icon: 'bg-surface-3 text-muted border-border-strong', text: 'text-text', bar: 'bg-faint' },
}

/**
 * KPI card. Doubles as a filter: clicking toggles the matching status filter,
 * which is why it accepts onClick/active.
 */
export function Kpi({ label, value, hint, icon, tone = 'accent', progress, onClick, active, delta }: KpiProps) {
  const t = TONE[tone]
  const inner = (
    <>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-2xs font-medium uppercase tracking-wide text-muted">
            {label}
            {active ? <span className="rounded-sm bg-accent/15 px-1 text-3xs normal-case text-accent">filtered</span> : null}
          </div>
          <div className={cn('mt-1.5 text-2xl font-semibold leading-none tracking-tight tabular-nums', t.text)}>
            {value}
          </div>
        </div>
        <div className={cn('flex h-8 w-8 shrink-0 items-center justify-center rounded border', t.icon)}>
          <Icon name={icon} size={15} />
        </div>
      </div>

      <div className="mt-2.5 flex min-h-[16px] items-center justify-between gap-2">
        <div className="truncate text-2xs text-muted">{hint}</div>
        {delta ? <div className="shrink-0 text-2xs">{delta}</div> : null}
      </div>

      {progress !== undefined ? (
        <div className="mt-2 h-0.5 w-full overflow-hidden rounded-full bg-surface-3" aria-hidden="true">
          <div
            className={cn('h-full rounded-full transition-[width] duration-500', t.bar)}
            style={{ width: `${Math.max(0, Math.min(100, progress))}%` }}
          />
        </div>
      ) : null}
    </>
  )

  if (!onClick) {
    return <div className="tg-card p-3.5">{inner}</div>
  }

  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'tg-card p-3.5 text-left transition-colors',
        active ? 'border-accent/50 bg-accent/[0.04]' : 'hover:border-border-strong hover:bg-surface-2/40',
      )}
    >
      {inner}
    </button>
  )
}
