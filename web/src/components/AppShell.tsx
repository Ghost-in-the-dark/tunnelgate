import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, clearSession, friendlyMessage } from '../lib/api'
import { useAuth } from '../lib/hooks'
import { cn } from '../lib/cn'
import { Icon } from './Icon'
import type { IconName } from './Icon'
import { Button } from './Button'
import { useToast } from './Toast'

interface NavEntry {
  to: string
  label: string
  icon: IconName
  /** Only admins see Settings (it holds the user list). */
  adminOnly?: boolean
}

const NAV: NavEntry[] = [
  { to: '/hosts', label: 'Hosts', icon: 'hosts' },
  { to: '/automations', label: 'Automations', icon: 'automations' },
  { to: '/access', label: 'Access', icon: 'access' },
  { to: '/audit', label: 'Audit', icon: 'audit' },
  { to: '/settings', label: 'Settings', icon: 'settings', adminOnly: true },
]

export function AppShell() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const toast = useToast()
  const [userMenu, setUserMenu] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!userMenu) return
    const close = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) setUserMenu(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setUserMenu(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', onKey)
    }
  }, [userMenu])

  const logout = async () => {
    try {
      await api.logout()
    } catch (err) {
      // A failed logout must still clear local state - otherwise the UI lies.
      toast.error(friendlyMessage(err))
    } finally {
      clearSession()
      navigate('/login', { replace: true })
    }
  }

  const visibleNav = NAV.filter((n) => !n.adminOnly || user?.role === 'admin')

  return (
    <div className="flex h-full min-h-0 bg-bg">
      <a href="#main" className="tg-skip-link">
        Skip to content
      </a>

      {/* ---------------------------------------------------------- icon rail */}
      <nav
        aria-label="Primary"
        className="flex w-14 shrink-0 flex-col items-center gap-1 border-r border-border bg-surface/60 py-3"
      >
        <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-accent-gradient shadow-sm">
          <Icon name="activity" size={18} className="text-white" />
        </div>

        {visibleNav.map((entry) => (
          <NavLink
            key={entry.to}
            to={entry.to}
            title={entry.label}
            aria-label={entry.label}
            className={({ isActive }) =>
              cn(
                'group relative flex h-10 w-10 items-center justify-center rounded-lg transition-colors',
                isActive
                  ? 'bg-accent/12 text-accent'
                  : 'text-muted hover:bg-surface-2 hover:text-text',
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive ? (
                  <span
                    aria-hidden="true"
                    className="absolute -left-[9px] h-6 w-[3px] rounded-r-full bg-accent"
                  />
                ) : null}
                <Icon name={entry.icon} size={18} />
                {/* Tooltip on hover/focus: the rail is icon-only to save width. */}
                <span
                  role="tooltip"
                  className="pointer-events-none absolute left-full z-40 ml-2 hidden whitespace-nowrap rounded border border-border bg-surface px-2 py-1 text-2xs text-text shadow-pop group-hover:block group-focus-visible:block"
                >
                  {entry.label}
                </span>
              </>
            )}
          </NavLink>
        ))}

        <div className="mt-auto" ref={menuRef}>
          <button
            type="button"
            onClick={() => setUserMenu((v) => !v)}
            aria-haspopup="menu"
            aria-expanded={userMenu}
            aria-label={`Account menu for ${user?.username ?? 'user'}`}
            className="flex h-9 w-9 items-center justify-center rounded-full border border-border-strong bg-surface-3 text-xs font-semibold uppercase text-text transition-colors hover:border-accent/60"
          >
            {(user?.display_name ?? user?.username ?? '?').slice(0, 2)}
          </button>

          {userMenu ? (
            <div
              role="menu"
              className="absolute bottom-14 left-14 z-50 w-56 animate-pop-in rounded border border-border bg-surface p-1 shadow-pop"
            >
              <div className="border-b border-border px-2 py-2">
                <div className="truncate text-xs font-medium text-text">
                  {user?.display_name ?? user?.username}
                </div>
                <div className="mt-0.5 flex items-center gap-1.5 text-2xs text-muted">
                  <Icon name="shield" size={10} />
                  <span className="capitalize">{user?.role}</span>
                  <span aria-hidden="true">·</span>
                  <span className="truncate">{user?.username}</span>
                </div>
              </div>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setUserMenu(false)
                  navigate('/settings')
                }}
                className="mt-1 flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs text-text hover:bg-surface-2"
              >
                <Icon name="user" size={13} />
                Account settings
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={logout}
                className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs text-danger hover:bg-danger/10"
              >
                <Icon name="logout" size={13} />
                Sign out
              </button>
            </div>
          ) : null}
        </div>
      </nav>

      {/* ---------------------------------------------------------- content */}
      <main id="main" className="flex min-w-0 flex-1 flex-col">
        <Outlet />
      </main>
    </div>
  )
}

/**
 * Top bar shared by every panel screen: a real global search that jumps to /hosts
 * (the only searchable collection today) plus the live fleet counters.
 */
export function TopBar({
  search,
  onSearchChange,
  placeholder = 'Search hosts, groups, IPs…',
  children,
}: {
  search?: string
  onSearchChange?: (v: string) => void
  placeholder?: string
  children?: React.ReactNode
}) {
  const inputRef = useRef<HTMLInputElement>(null)

  // "/" focuses search, the way every infra console does it.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      const typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target?.isContentEditable === true
      if (e.key === '/' && !typing && onSearchChange) {
        e.preventDefault()
        inputRef.current?.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onSearchChange])

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-border bg-surface/40 px-4">
      <div className="relative min-w-0 max-w-md flex-1">
        <Icon
          name="search"
          size={14}
          className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint"
        />
        <input
          ref={inputRef}
          name="q"
          type="search"
          value={search ?? ''}
          onChange={(e) => onSearchChange?.(e.target.value)}
          placeholder={placeholder}
          aria-label="Search"
          className="h-8 w-full rounded border border-border bg-surface-2 pl-8 pr-8 text-xs text-text placeholder:text-faint transition-colors hover:border-border-strong focus:border-accent focus:outline-none focus-visible:outline-none"
        />
        <span className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 sm:block">
          <kbd className="tg-kbd">/</kbd>
        </span>
      </div>
      <div className="ml-auto flex items-center gap-4">{children}</div>
    </header>
  )
}

/** Fleet counters in the top bar, fed by the router list envelope. */
export function FleetCounters({
  online,
  offline,
  pending,
}: {
  online: number
  offline: number
  pending: number
}) {
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: ({ signal }) => api.stats(signal),
    refetchInterval: 10_000,
  })
  const consoleActive = stats?.console_sessions_active ?? 0

  return (
    <div className="flex items-center gap-3.5 text-2xs" aria-live="off">
      <Counter label="Online" value={online} dot="bg-success" />
      <Counter label="Offline" value={offline} dot="bg-danger" />
      <Counter label="Pending" value={pending} dot="bg-warning" />
      {consoleActive > 0 ? (
        <span
          className="flex items-center gap-1.5 rounded-sm border border-accent/30 bg-accent/10 px-1.5 py-0.5 text-accent"
          title="Interactive console sessions currently open on the panel"
        >
          <Icon name="terminal" size={11} />
          {consoleActive} console
        </span>
      ) : null}
    </div>
  )
}

function Counter({ label, value, dot }: { label: string; value: number; dot: string }) {
  return (
    <span className="flex items-center gap-1.5" title={`${value} ${label.toLowerCase()} routers`}>
      <span className={cn('h-1.5 w-1.5 rounded-full', dot)} aria-hidden="true" />
      <span className="sr-only">{label}:</span>
      <span className="font-semibold tabular-nums text-text">{value}</span>
      <span className="hidden text-muted md:inline">{label}</span>
    </span>
  )
}

/** Placeholder screen for rail entries that are out of scope for this build. */
export function ComingSoon({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex h-full flex-col">
      <TopBar search="" onSearchChange={undefined} placeholder="Search…">
        <span className="text-2xs uppercase tracking-wide text-muted">planned</span>
      </TopBar>
      <div className="flex flex-1 items-center justify-center p-8">
        <div className="max-w-md text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-lg border border-border bg-surface-2 text-muted">
            <Icon name="activity" size={22} />
          </div>
          <h1 className="text-base font-semibold">{title}</h1>
          <p className="mt-2 text-xs leading-relaxed text-muted">{description}</p>
          <Button className="mt-5" variant="secondary" icon="hosts" onClick={() => (window.location.href = '/hosts')}>
            Back to hosts
          </Button>
        </div>
      </div>
    </div>
  )
}
