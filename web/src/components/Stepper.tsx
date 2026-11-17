import { cn } from '../lib/cn'
import { Icon } from './Icon'

export interface StepDef {
  id: number
  label: string
  description?: string
}

/**
 * Horizontal stepper for the wizard header: completed / current / upcoming.
 * Keyboard users get an ordered list; only the current step is emphasised.
 */
export function Stepper({
  steps,
  current,
  onStepClick,
  maxReached,
}: {
  steps: StepDef[]
  current: number
  onStepClick?: (step: number) => void
  /** Highest step the user may navigate back/forward to. */
  maxReached: number
}) {
  return (
    <nav aria-label="Install progress">
      <ol className="flex flex-wrap items-center gap-x-1 gap-y-2">
        {steps.map((step, i) => {
          const done = step.id < current
          const active = step.id === current
          const reachable = step.id <= maxReached
          const Wrapper = onStepClick && reachable && !active ? 'button' : 'div'
          return (
            <li key={step.id} className="flex items-center gap-1">
              <Wrapper
                {...(Wrapper === 'button'
                  ? {
                      type: 'button' as const,
                      onClick: () => onStepClick?.(step.id),
                      className: cn(
                        'flex items-center gap-2 rounded px-1.5 py-1 text-left transition-colors hover:bg-surface-2',
                        'cursor-pointer',
                      ),
                    }
                  : { className: 'flex items-center gap-2 px-1.5 py-1' })}
                aria-current={active ? 'step' : undefined}
              >
                <span
                  className={cn(
                    'flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-2xs font-semibold transition-colors',
                    done && 'border-success/40 bg-success/15 text-success',
                    active && 'border-accent bg-accent text-white',
                    !done && !active && 'border-border-strong bg-surface-2 text-faint',
                  )}
                  aria-hidden="true"
                >
                  {done ? <Icon name="check" size={12} /> : step.id}
                </span>
                <span className="min-w-0">
                  <span
                    className={cn(
                      'block whitespace-nowrap text-xs font-medium',
                      active ? 'text-text' : done ? 'text-muted' : 'text-faint',
                    )}
                  >
                    {step.label}
                  </span>
                  {step.description ? (
                    <span className="block whitespace-nowrap text-3xs text-faint">{step.description}</span>
                  ) : null}
                </span>
              </Wrapper>
              {i < steps.length - 1 ? (
                <span
                  aria-hidden="true"
                  className={cn('mx-1 h-px w-6 sm:w-10', done ? 'bg-success/40' : 'bg-border')}
                />
              ) : null}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

/** Vertical phase stepper used by the connection-watch step and the detail timeline. */
export interface PhaseStep {
  label: string
  detail?: string
  state: 'done' | 'current' | 'todo' | 'error'
}

export function VerticalStepper({ steps }: { steps: PhaseStep[] }) {
  return (
    <ol className="space-y-0" aria-live="polite">
      {steps.map((s, i) => (
        <li key={s.label} className="flex gap-3">
          <div className="flex flex-col items-center">
            <span
              className={cn(
                'flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-3xs',
                s.state === 'done' && 'border-success/50 bg-success/15 text-success',
                s.state === 'current' && 'border-accent bg-accent/15 text-accent',
                s.state === 'todo' && 'border-border-strong bg-surface-2 text-faint',
                s.state === 'error' && 'border-danger/50 bg-danger/15 text-danger',
              )}
            >
              {s.state === 'done' ? (
                <Icon name="check" size={10} />
              ) : s.state === 'current' ? (
                <Icon name="spinner" size={10} className="animate-spin" />
              ) : s.state === 'error' ? (
                <Icon name="x" size={10} />
              ) : (
                <span className="h-1 w-1 rounded-full bg-current" />
              )}
            </span>
            {i < steps.length - 1 ? (
              <span
                className={cn('my-0.5 w-px flex-1 min-h-[14px]', s.state === 'done' ? 'bg-success/35' : 'bg-border')}
                aria-hidden="true"
              />
            ) : null}
          </div>
          <div className={cn('pb-3', i === steps.length - 1 && 'pb-0')}>
            <div
              className={cn(
                'text-xs font-medium leading-5',
                s.state === 'todo' ? 'text-faint' : s.state === 'error' ? 'text-danger' : 'text-text',
              )}
            >
              {s.label}
            </div>
            {s.detail ? <div className="mt-0.5 text-2xs leading-relaxed text-muted">{s.detail}</div> : null}
          </div>
        </li>
      ))}
    </ol>
  )
}
