import { useCallback, useEffect, useRef, useState } from 'react'
import { getAuthState, subscribeAuth } from './api'

/** Subscribes a component to the in-memory auth store. */
export function useAuth() {
  const [state, setState] = useState(getAuthState)
  useEffect(() => {
    setState(getAuthState())
    return subscribeAuth(setState)
  }, [])
  return state
}

/**
 * Re-renders every `ms` so relative timestamps ("4s ago") stay honest without
 * each row owning a timer. One interval for the whole table.
 */
export function useNow(ms = 5000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), ms)
    return () => window.clearInterval(id)
  }, [ms])
  return now
}

/** Countdown that keeps ticking to zero; negative values clamp at 0 and flip `expired`. */
export function useCountdown(targetIso: string | null | undefined) {
  const target = targetIso ? Date.parse(targetIso) : NaN
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (Number.isNaN(target)) return
    setNow(Date.now())
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [target])
  const secondsLeft = Number.isNaN(target) ? null : Math.max(0, Math.round((target - now) / 1000))
  return { secondsLeft, expired: secondsLeft === 0 }
}

/** Debounces a fast-changing value (search boxes). */
export function useDebounced<T>(value: T, delay = 250): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(id)
  }, [value, delay])
  return debounced
}

export function useLocalStorage<T>(key: string, initial: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = window.localStorage.getItem(key)
      return raw === null ? initial : (JSON.parse(raw) as T)
    } catch {
      return initial
    }
  })
  const set = useCallback(
    (next: T) => {
      setValue(next)
      try {
        window.localStorage.setItem(key, JSON.stringify(next))
      } catch {
        /* private mode / quota: preferences just do not persist */
      }
    },
    [key],
  )
  return [value, set]
}

/** Calls `fn` on an interval while `enabled` - used by the wizard poll loop. */
export function useInterval(fn: () => void, ms: number | null) {
  const saved = useRef(fn)
  useEffect(() => {
    saved.current = fn
  }, [fn])
  useEffect(() => {
    if (ms === null) return
    const id = window.setInterval(() => saved.current(), ms)
    return () => window.clearInterval(id)
  }, [ms])
}

/** Escape-key handler for dialogs and the console page. */
export function useEscape(handler: () => void, enabled = true) {
  useEffect(() => {
    if (!enabled) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') handler()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [handler, enabled])
}

export function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches
}
