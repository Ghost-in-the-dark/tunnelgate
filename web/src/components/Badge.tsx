import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Icon } from './Icon'
import type { IconName } from './Icon'

type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent'

const TONES: Record<Tone, string> = {
  neutral: 'border-border-strong/70 bg-surface-3 text-muted',
  success: 'border-success/30 bg-success/10 text-success',
  warning: 'border-warning/30 bg-warning/10 text-warning',
  danger: 'border-danger/30 bg-danger/10 text-danger',
  accent: 'border-accent/35 bg-accent/10 text-accent',
}

export function Badge({
  tone = 'neutral',
  children,
  icon,
  className,
  mono,
  title,
}: {
  tone?: Tone
  children: ReactNode
  icon?: IconName
  className?: string
  mono?: boolean
  title?: string
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex max-w-full items-center gap-1 truncate rounded-sm border px-1.5 py-0.5 text-2xs font-medium leading-4',
        TONES[tone],
        mono && 'font-mono',
        className,
      )}
    >
      {icon ? <Icon name={icon} size={11} className="shrink-0" /> : null}
      <span className="truncate">{children}</span>
    </span>
  )
}

export type ConnectionState = 'online' | 'offline' | 'pending' | 'awaiting'

/**
 * The table's status pill. A dot carries the colour and the text carries the meaning,
 * so the state survives greyscale and colour-blind viewing (never colour alone).
 */
export function StatusPill({ state, className }: { state: ConnectionState; className?: string }) {
  const map: Record<ConnectionState, { label: string; dot: string; text: string; ring: string }> = {
    online: {
      label: 'Online',
      dot: 'bg-success',
      text: 'text-success',
      ring: 'border-success/25 bg-success/[0.07]',
    },
    offline: {
      label: 'Offline',
      dot: 'bg-danger',
      text: 'text-danger',
      ring: 'border-danger/25 bg-danger/[0.07]',
    },
    awaiting: {
      label: 'Awaiting key',
      dot: 'bg-warning',
      text: 'text-warning',
      ring: 'border-warning/25 bg-warning/[0.07]',
    },
    pending: {
      label: 'Pending',
      dot: 'bg-warning',
      text: 'text-warning',
      ring: 'border-warning/25 bg-warning/[0.07]',
    },
  }
  const s = map[state]
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-2xs font-medium',
        s.ring,
        s.text,
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', s.dot, state === 'online' && 'animate-pulse')} />
      {s.label}
    </span>
  )
}

/** Maps the server status string onto the four pills the UI knows about. */
export function pillStateFor(status: string): ConnectionState {
  switch (status) {
    case 'online':
      return 'online'
    case 'offline':
      return 'offline'
    case 'awaiting':
      return 'awaiting'
    default:
      return 'pending'
  }
}
