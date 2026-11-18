import { useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ApiError, DEFAULT_RETRY_AFTER, api, friendlyMessage, setSession } from '../lib/api'
import { useAuth } from '../lib/hooks'
import { Button } from '../components/Button'
import { TextField } from '../components/Field'
import { InlineAlert } from '../components/States'
import { Icon } from '../components/Icon'

interface LocationState {
  from?: { pathname: string; search?: string }
}

/**
 * Accept only a same-origin absolute path as a post-sign-in destination: one leading
 * slash and not two. Rejects protocol-relative '//evil.example' and the backslash
 * variant '/\evil.example' that browsers normalise to the same thing, so a crafted
 * ?next= cannot turn the login page into an open redirect.
 */
function safeNext(raw: string | null): string | null {
  if (!raw || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return null
  return raw
}

export function LoginPage() {
  const { bootState, user } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fieldError, setFieldError] = useState<{ username?: string; password?: string }>({})
  const [submitting, setSubmitting] = useState(false)
  const [retryAfter, setRetryAfter] = useState<number | null>(null)
  const usernameRef = useRef<HTMLInputElement>(null)

  // Count the 429 cooldown down to zero, then let the form submit again.
  useEffect(() => {
    if (retryAfter === null) return
    if (retryAfter <= 0) {
      setRetryAfter(null)
      return
    }
    const id = window.setTimeout(() => setRetryAfter((n) => (n === null ? null : n - 1)), 1000)
    return () => window.clearTimeout(id)
  }, [retryAfter])

  useEffect(() => {
    usernameRef.current?.focus()
  }, [])

  const state = location.state as LocationState | null
  const fromState = state?.from ? `${state.from.pathname}${state.from.search ?? ''}` : null

  // The nginx auth gate redirects to /login?router=<slug>&next=<original URI> when a
  // router vhost rejects an anonymous request. RequireAuth records the destination in
  // history state instead, so fall back to ?next= to keep the operator's original page.
  //
  // With ?router= present, `next` is a path on the ROUTER, not on this panel: applying it
  // here would 404 the panel and, worse, the resulting session cookie would still not be
  // valid over there. /__tg/launch is the handoff that mints a single-use ticket and sends
  // the browser to that router's own host, where the path actually means something.
  const params = new URLSearchParams(location.search)
  const routerSlug = params.get('router')
  const nextPath = safeNext(params.get('next'))
  const handoff =
    !fromState && routerSlug
      ? `/__tg/launch?router=${encodeURIComponent(routerSlug)}&next=${encodeURIComponent(nextPath ?? '/')}`
      : null
  const from = fromState ?? handoff ?? nextPath ?? '/hosts'

  // A /__tg/ path is a server endpoint, not an SPA route, so it needs a real navigation:
  // react-router would swap in the not-found page instead of ever reaching FastAPI.
  const leave = (dest: string) => {
    if (dest.startsWith('/__tg/')) window.location.assign(dest)
    else navigate(dest, { replace: true })
  }

  // Already signed in and bounced here by a router vhost: skip the form and complete the
  // handoff immediately, otherwise the operator has to sign in a second time for nothing.
  useEffect(() => {
    if (bootState === 'authenticated' && handoff) window.location.replace(handoff)
  }, [bootState, handoff])

  if (bootState === 'authenticated' && user) {
    if (handoff) return <p className="p-10 text-center text-xs text-muted">Opening your router…</p>
    return <Navigate to={from} replace />
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (retryAfter !== null) return
    setError(null)
    setFieldError({})

    const nextFieldErrors: { username?: string; password?: string } = {}
    if (!username.trim()) nextFieldErrors.username = 'Enter your username.'
    if (!password) nextFieldErrors.password = 'Enter your password.'
    if (Object.keys(nextFieldErrors).length > 0) {
      setFieldError(nextFieldErrors)
      return
    }

    setSubmitting(true)
    try {
      const session = await api.login(username.trim(), password)
      setSession(session)
      // `from` is history state recorded by RequireAuth or a same-origin path vetted by
      // safeNext(), so this navigation cannot leave the panel; a router handoff is a
      // same-origin /__tg/launch URL, which the server answers with a 303 to the router.
      leave(from)
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setRetryAfter(err.retryAfter ?? DEFAULT_RETRY_AFTER)
        setError(null)
      } else if (err instanceof ApiError && err.status === 401) {
        // Do not leak whether the username exists.
        setError('Wrong username or password.')
      } else {
        setError(friendlyMessage(err))
      }
      setPassword('')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="relative flex min-h-full items-center justify-center overflow-hidden bg-bg px-4 py-10">
      {/* Ambient accent glow - purely decorative, hidden from AT. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute left-1/2 top-0 h-[420px] w-[720px] -translate-x-1/2 rounded-full bg-accent/10 blur-[120px]"
      />

      <div className="relative w-full max-w-sm">
        <div className="mb-7 flex flex-col items-center text-center">
          <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-lg bg-accent-gradient shadow-sm">
            <Icon name="activity" size={22} className="text-white" />
          </div>
          <h1 className="text-lg font-semibold tracking-tight text-text">TunnelGate</h1>
          <p className="mt-1 text-xs text-muted">Centralised LuCI access over SSH reverse tunnels</p>
        </div>

        <div className="tg-card p-5">
          <form onSubmit={submit} noValidate>
            {error ? (
              <InlineAlert tone="danger" className="mb-4">
                {error}
              </InlineAlert>
            ) : null}

            {handoff ? (
              <InlineAlert tone="info" className="mb-4">
                Sign in to open <strong>{routerSlug}</strong>. You are signing in here; the
                router gets its own short-lived session and never sees this cookie.
              </InlineAlert>
            ) : null}

            {retryAfter !== null ? (
              <InlineAlert tone="warning" title="Too many sign-in attempts" className="mb-4">
                For security, this address is temporarily locked. Try again in{' '}
                <strong className="tabular-nums text-warning">{retryAfter}s</strong>.
              </InlineAlert>
            ) : null}

            <div className="space-y-3.5">
              <TextField
                ref={usernameRef}
                label="Username"
                name="username"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                error={fieldError.username}
                disabled={submitting}
              />

              <div>
                <div className="relative">
                  <TextField
                    label="Password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    error={fieldError.password}
                    disabled={submitting}
                    className="[&_input]:pr-9"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    aria-pressed={showPassword}
                    className="absolute right-2 top-[30px] rounded p-1 text-muted transition-colors hover:text-text"
                  >
                    <Icon name={showPassword ? 'eye-off' : 'eye'} size={14} />
                  </button>
                </div>
              </div>
            </div>

            <Button
              type="submit"
              variant="primary"
              size="lg"
              className="mt-5 w-full justify-center"
              loading={submitting}
              disabled={retryAfter !== null}
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </div>

        <p className="mt-5 text-center text-2xs leading-relaxed text-faint">
          Access is logged. Session cookies are HttpOnly and CSRF-protected.
        </p>
      </div>
    </div>
  )
}
