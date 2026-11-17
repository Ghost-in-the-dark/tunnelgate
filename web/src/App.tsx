import { Suspense, lazy, useEffect, useState } from 'react'
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api, clearSession, getAuthState, setSession } from './lib/api'
import { useAuth } from './lib/hooks'
import { AppShell, ComingSoon } from './components/AppShell'
import { Icon } from './components/Icon'
import { Spinner } from './components/States'
import { LoginPage } from './pages/Login'
import { HostsPage } from './pages/Hosts'

/**
 * The terminal pulls in xterm (~250 kB), the wizard and the detail page pull in
 * a lot of form code. None of it is needed to render the host list, so each
 * heavy screen is its own chunk and the first paint stays small.
 */
const NewRouterPage = lazy(() =>
  import('./pages/NewRouter').then((m) => ({ default: m.NewRouterPage })),
)
const RouterDetailPage = lazy(() =>
  import('./pages/RouterDetail').then((m) => ({ default: m.RouterDetailPage })),
)
const ConsolePage = lazy(() => import('./pages/Console').then((m) => ({ default: m.ConsolePage })))
const AuditPage = lazy(() => import('./pages/Audit').then((m) => ({ default: m.AuditPage })))
const SettingsPage = lazy(() => import('./pages/Settings').then((m) => ({ default: m.SettingsPage })))

/**
 * One GET /api/auth/me before the first protected render. Without it every
 * screen would flash 401-driven redirects on reload.
 */
function useAuthBootstrap() {
  const [ready, setReady] = useState(() => getAuthState().bootState !== 'unknown')
  const queryClient = useQueryClient()

  useEffect(() => {
    if (ready) return
    let cancelled = false
    api
      .me()
      .then((session) => {
        if (cancelled) return
        setSession(session)
      })
      .catch(() => {
        if (cancelled) return
        clearSession()
        queryClient.clear()
      })
      .finally(() => {
        if (!cancelled) setReady(true)
      })
    return () => {
      cancelled = true
    }
  }, [ready, queryClient])

  return ready
}

function BootSplash() {
  return (
    <div className="flex h-full items-center justify-center bg-bg">
      <div className="flex flex-col items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent-gradient shadow-card">
          <Icon name="activity" size={20} className="text-white" />
        </div>
        <div className="flex items-center gap-2 text-2xs text-muted">
          <Spinner size={12} />
          Starting the panel…
        </div>
      </div>
    </div>
  )
}

/** Blocks protected children until the session is known; remembers where you were. */
function RequireAuth({ children }: { children: React.ReactNode }) {
  const { bootState, user } = useAuth()
  const location = useLocation()

  if (bootState === 'unknown') return <BootSplash />
  if (!user) {
    return <Navigate to="/login" replace state={{ from: { pathname: location.pathname, search: location.search } }} />
  }
  return <>{children}</>
}

function PageFallback() {
  return (
    <div className="flex h-full items-center justify-center bg-bg">
      <div className="flex items-center gap-2 text-2xs text-muted">
        <Spinner size={13} />
        Loading…
      </div>
    </div>
  )
}

function NotFound() {
  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-1 items-center justify-center p-8">
        <div className="max-w-md text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-lg border border-border bg-surface-2 font-mono text-sm text-muted">
            404
          </div>
          <h1 className="text-base font-semibold text-text">This page does not exist</h1>
          <p className="mt-2 text-xs leading-relaxed text-muted">
            The link may be stale, or the router it pointed at was deleted. The host list is the way back.
          </p>
          <a
            href="/hosts"
            className="mt-5 inline-flex items-center gap-1.5 rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-text transition-colors hover:border-border-strong"
          >
            <Icon name="hosts" size={13} />
            Back to hosts
          </a>
        </div>
      </div>
    </div>
  )
}

/** Applies the stored theme before the shell paints, so there is no flash. */
export function useThemeBoot() {
  useEffect(() => {
    let stored: 'dark' | 'light' = 'dark'
    try {
      const raw = window.localStorage.getItem('tg-theme')
      if (raw === '"light"' || raw === 'light') stored = 'light'
    } catch {
      /* private mode - stay on the default */
    }
    const root = document.documentElement
    root.classList.toggle('light', stored === 'light')
    root.classList.toggle('dark', stored === 'dark')
    root.setAttribute('data-theme', stored)
  }, [])
}

export function App() {
  const ready = useAuthBootstrap()
  useThemeBoot()

  if (!ready) return <BootSplash />

  return (
    <BrowserRouter>
      <Suspense fallback={<PageFallback />}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />

          <Route
            element={
              <RequireAuth>
                <AppShell />
              </RequireAuth>
            }
          >
            <Route path="/hosts" element={<HostsPage />} />
            <Route path="/routers/new" element={<NewRouterPage />} />
            <Route path="/routers/:id" element={<RouterDetailPage />} />
            <Route path="/routers/:id/console" element={<ConsolePage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/settings" element={<SettingsPage />} />

            <Route
              path="/automations"
              element={
                <ComingSoon
                  title="Automations"
                  description="Scheduled actions - rotating keys on a cadence, re-running a health check when a router flaps, or opening a tunnel for a maintenance window. Nothing here is wired yet; the rail entry exists so the shape of the panel is honest about where it is going."
                />
              }
            />
            <Route
              path="/access"
              element={
                <ComingSoon
                  title="Access"
                  description="Who may reach which router, and from where. Today access is all-or-nothing per panel role; per-router ACLs and time-boxed grants are planned but not implemented."
                />
              }
            />
          </Route>

          <Route path="/" element={<Navigate to="/hosts" replace />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  )
}
