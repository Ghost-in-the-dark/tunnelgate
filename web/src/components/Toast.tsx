import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { cn } from '../lib/cn'
import { Icon } from './Icon'

type Tone = 'success' | 'danger' | 'info'

interface Toast {
  id: number
  tone: Tone
  message: string
}

interface ToastApi {
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
}

const ToastContext = createContext<ToastApi | null>(null)

/**
 * Toasts are for confirmations that do not need a decision ("Key rotated").
 * Anything that needs a decision uses a dialog instead.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)

  const push = useCallback((tone: Tone, message: string) => {
    const id = nextId.current++
    setToasts((prev) => [...prev.slice(-2), { id, tone, message }])
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 5000)
  }, [])

  const api = useMemo<ToastApi>(
    () => ({
      success: (m) => push('success', m),
      error: (m) => push('danger', m),
      info: (m) => push('info', m),
    }),
    [push],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2"
        role="region"
        aria-label="Notifications"
      >
        {toasts.map((t) => (
          <ToastRow key={t.id} toast={t} onDismiss={() => setToasts((p) => p.filter((x) => x.id !== t.id))} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

function ToastRow({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const id = useId()
  const map: Record<Tone, { cls: string; icon: 'check-circle' | 'alert' | 'info' }> = {
    success: { cls: 'border-success/40 text-success', icon: 'check-circle' },
    danger: { cls: 'border-danger/40 text-danger', icon: 'alert' },
    info: { cls: 'border-accent/40 text-accent', icon: 'info' },
  }
  const m = map[toast.tone]
  return (
    <div
      className={cn(
        'pointer-events-auto flex animate-pop-in items-start gap-2 rounded border bg-surface px-3 py-2.5 shadow-pop',
        m.cls,
      )}
      role={toast.tone === 'danger' ? 'alert' : 'status'}
      aria-live={toast.tone === 'danger' ? 'assertive' : 'polite'}
      id={id}
    >
      <Icon name={m.icon} size={14} className="mt-px shrink-0" />
      <p className="flex-1 text-xs leading-relaxed text-text">{toast.message}</p>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss notification"
        className="rounded p-0.5 text-muted hover:text-text"
      >
        <Icon name="x" size={12} />
      </button>
    </div>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>')
  return ctx
}

/** Announce a value change to screen readers without moving focus. */
export function LiveRegion({ children, politeness = 'polite' }: { children: ReactNode; politeness?: 'polite' | 'assertive' }) {
  const [content, setContent] = useState(children)
  useEffect(() => setContent(children), [children])
  return (
    <span className="sr-only" aria-live={politeness} aria-atomic="true">
      {content}
    </span>
  )
}
