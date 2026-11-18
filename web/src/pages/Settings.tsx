import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, fieldErrors, friendlyMessage } from '../lib/api'
import type {
  AgentEndpointInput,
  AgentEndpointResult,
  AgentEndpointTest,
  AgentScheme,
  PanelConfig,
  Role,
  User,
} from '../lib/types'
import { useAuth, useLocalStorage } from '../lib/hooks'
import { cn } from '../lib/cn'
import { absoluteTime, relativeTime } from '../lib/format'
import { TopBar } from '../components/AppShell'
import { Badge } from '../components/Badge'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { SelectField, TextField } from '../components/Field'
import { ActionMenu } from '../components/Menu'
import { ConfirmDialog, Modal } from '../components/Modal'
import { EmptyState, ErrorState, InlineAlert, Skeleton } from '../components/States'
import { useToast } from '../components/Toast'

const TABS = [
  { id: 'account', label: 'Account', icon: 'user' },
  { id: 'users', label: 'Users', icon: 'shield', adminOnly: true },
  { id: 'panel', label: 'Panel', icon: 'settings' },
] as const

type TabId = (typeof TABS)[number]['id']

const ROLE_HELP: Record<Role, string> = {
  admin: 'Full control: routers, users, panel settings and audit history.',
  operator: 'May create routers, rotate keys, open consoles. Cannot manage users.',
  viewer: 'Read-only. Sees routers and audit history, cannot change anything.',
}

export function SettingsPage() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [tab, setTab] = useState<TabId>('account')

  const visibleTabs = TABS.filter((t) => !('adminOnly' in t && t.adminOnly) || isAdmin)
  const activeTab: TabId = visibleTabs.some((t) => t.id === tab) ? tab : 'account'

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar placeholder="Search hosts…" />

      <header className="border-b border-border px-4 pt-4">
        <h1 className="text-base font-semibold tracking-tight text-text">Settings</h1>
        <p className="mt-0.5 text-2xs text-muted">
          Your account, the people who can reach this panel, and how it is wired.
        </p>
        <nav className="mt-3 flex gap-0.5" role="tablist" aria-label="Settings sections">
          {visibleTabs.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={activeTab === t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                'relative flex items-center gap-1.5 rounded-t px-3 py-2 text-xs font-medium transition-colors',
                activeTab === t.id
                  ? 'bg-bg text-text'
                  : 'text-muted hover:bg-surface-2/60 hover:text-text',
              )}
            >
              <Icon name={t.icon} size={13} />
              {t.label}
              {activeTab === t.id ? (
                <span aria-hidden="true" className="absolute inset-x-0 -bottom-px h-0.5 bg-accent" />
              ) : null}
            </button>
          ))}
        </nav>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto bg-bg">
        {activeTab === 'account' ? <AccountTab /> : null}
        {activeTab === 'users' && isAdmin ? <UsersTab currentUserId={user?.id ?? -1} /> : null}
        {activeTab === 'panel' ? <PanelTab /> : null}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------- account */
function AccountTab() {
  const toast = useToast()
  const queryClient = useQueryClient()
  const { user } = useAuth()

  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [errors, setErrors] = useState<Record<string, string>>({})

  const [theme, setTheme] = useLocalStorage<'dark' | 'light'>('tg-theme', 'dark')

  useEffect(() => {
    const root = document.documentElement
    root.classList.toggle('light', theme === 'light')
    root.classList.toggle('dark', theme === 'dark')
    root.setAttribute('data-theme', theme)
  }, [theme])

  const mutation = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setConfirm('')
      setErrors({})
      toast.success('Password changed. Other sessions stay signed in until they expire.')
      void queryClient.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (err) => {
      const fields = fieldErrors(err)
      if (Object.keys(fields).length > 0) setErrors(fields)
      else toast.error(friendlyMessage(err))
    },
  })

  const strength = passwordStrength(next)
  const mismatch = confirm.length > 0 && confirm !== next

  return (
    <div className="max-w-2xl space-y-3 p-4">
      <section className="tg-card p-3.5">
        <h2 className="text-xs font-medium text-text">Signed in as</h2>
        <div className="mt-2 flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full border border-border-strong bg-surface-3 text-xs font-semibold uppercase text-text">
            {(user?.display_name ?? user?.username ?? '?').slice(0, 2)}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-xs font-medium text-text">
                {user?.display_name ?? user?.username}
              </span>
              <Badge tone={user?.role === 'admin' ? 'accent' : 'neutral'} mono>
                {user?.role}
              </Badge>
            </div>
            <div className="mt-0.5 font-mono text-3xs text-faint">{user?.username}</div>
          </div>
        </div>
        <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 border-t border-border pt-2.5">
          <div className="flex items-baseline justify-between gap-2">
            <dt className="text-3xs text-muted">Role</dt>
            <dd className="text-3xs text-text">{ROLE_HELP[(user?.role ?? 'viewer') as Role]}</dd>
          </div>
        </dl>
      </section>

      <form
        className="tg-card p-3.5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          const nextErrors: Record<string, string> = {}
          if (!current) nextErrors.current_password = 'Enter your current password.'
          if (next.length < 10) nextErrors.new_password = 'Use at least 10 characters.'
          if (next !== confirm) nextErrors.confirm = 'The two passwords do not match.'
          setErrors(nextErrors)
          if (Object.keys(nextErrors).length > 0) return
          mutation.mutate()
        }}
      >
        <div className="flex items-start justify-between gap-2">
          <div>
            <h2 className="text-xs font-medium text-text">Change password</h2>
            <p className="mt-0.5 text-2xs text-muted">
              You will stay signed in here; other browsers keep working until their session expires.
            </p>
          </div>
          <Button
            size="sm"
            variant="ghost"
            icon={show ? 'eye-off' : 'eye'}
            onClick={() => setShow((v) => !v)}
            type="button"
          >
            {show ? 'Hide' : 'Show'}
          </Button>
        </div>

        <div className="mt-3 space-y-3">
          <TextField
            label="Current password"
            name="current_password"
            markOptional={false}
            type={show ? 'text' : 'password'}
            autoComplete="current-password"
            value={current}
            error={errors.current_password}
            onChange={(e) => setCurrent(e.target.value)}
          />
          <div>
            <TextField
              label="New password"
              name="new_password"
              markOptional={false}
              type={show ? 'text' : 'password'}
              autoComplete="new-password"
              value={next}
              error={errors.new_password}
              onChange={(e) => setNext(e.target.value)}
            />
            {next.length > 0 ? <StrengthMeter score={strength} /> : null}
          </div>
          <TextField
            label="Repeat new password"
            name="confirm"
            markOptional={false}
            type={show ? 'text' : 'password'}
            autoComplete="new-password"
            value={confirm}
            error={errors.confirm ?? (mismatch ? 'The two passwords do not match.' : undefined)}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>

        <div className="mt-4 flex justify-end border-t border-border pt-3">
          <Button
            type="submit"
            size="sm"
            variant="primary"
            loading={mutation.isPending}
            disabled={!current || !next || !confirm}
          >
            Update password
          </Button>
        </div>
      </form>

      <section className="tg-card p-3.5">
        <h2 className="text-xs font-medium text-text">Appearance</h2>
        <p className="mt-0.5 text-2xs text-muted">
          The panel follows the theme you pick here on this browser only.
        </p>
        <div className="mt-2.5 flex items-center gap-2">
          {(['dark', 'light'] as const).map((option) => (
            <button
              key={option}
              type="button"
              aria-pressed={theme === option}
              onClick={() => setTheme(option)}
              className={cn(
                'flex items-center gap-2 rounded border px-3 py-2 text-xs transition-colors',
                theme === option
                  ? 'border-accent bg-accent/10 text-text'
                  : 'border-border bg-surface-2 text-muted hover:border-border-strong hover:text-text',
              )}
            >
              <span
                aria-hidden="true"
                className={cn(
                  'h-3.5 w-3.5 rounded-sm border',
                  option === 'dark'
                    ? 'border-slate-700 bg-slate-900'
                    : 'border-slate-300 bg-white',
                )}
              />
              {option === 'dark' ? 'Dark' : 'Light'}
              {theme === option ? <Icon name="check" size={12} className="text-accent" /> : null}
            </button>
          ))}
        </div>
      </section>
    </div>
  )
}

function passwordStrength(pw: string): 0 | 1 | 2 | 3 | 4 {
  if (pw.length === 0) return 0
  let score = 0
  if (pw.length >= 10) score += 1
  if (pw.length >= 14) score += 1
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score += 1
  return Math.min(4, score) as 0 | 1 | 2 | 3 | 4
}

function StrengthMeter({ score }: { score: 0 | 1 | 2 | 3 | 4 }) {
  const labels = ['too short', 'weak', 'fair', 'good', 'strong']
  const tones = ['bg-danger', 'bg-danger', 'bg-warning', 'bg-success', 'bg-success']
  return (
    <div className="mt-1.5 flex items-center gap-2">
      <div className="flex flex-1 gap-1" aria-hidden="true">
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={cn('h-1 flex-1 rounded-full', i < score ? tones[score] : 'bg-surface-3')}
          />
        ))}
      </div>
      <span className="w-16 text-right text-3xs text-muted" aria-live="polite">
        {labels[score]}
      </span>
    </div>
  )
}

/* --------------------------------------------------------------- users */
function normalizeUsers(data: { items: User[]; total?: number } | User[] | undefined): User[] {
  if (!data) return []
  return Array.isArray(data) ? data : data.items
}

function UsersTab({ currentUserId }: { currentUserId: number }) {
  const toast = useToast()
  const queryClient = useQueryClient()
  const usersQuery = useQuery({ queryKey: ['users'], queryFn: ({ signal }) => api.listUsers(signal) })

  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<User | null>(null)
  const [removing, setRemoving] = useState<User | null>(null)

  const users = useMemo(() => normalizeUsers(usersQuery.data), [usersQuery.data])

  const removeMutation = useMutation({
    mutationFn: (id: number) => api.deleteUser(id),
    onSuccess: () => {
      toast.success('User removed. Their sessions stop working immediately.')
      setRemoving(null)
      void queryClient.invalidateQueries({ queryKey: ['users'] })
      void queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
    onError: (err) => {
      setRemoving(null)
      toast.error(friendlyMessage(err))
    },
  })

  const toggleActive = useMutation({
    mutationFn: (u: User) => api.updateUser(u.id, { is_active: !u.is_active }),
    onSuccess: (u) => {
      toast.success(u.username + (u.is_active ? ' can sign in again.' : ' is disabled.'))
      void queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (err) => toast.error(friendlyMessage(err)),
  })

  if (usersQuery.error) {
    return <ErrorState error={usersQuery.error} onRetry={() => void usersQuery.refetch()} />
  }

  return (
    <div className="space-y-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-xs font-medium text-text">Panel users</h2>
          <p className="mt-0.5 text-2xs text-muted">
            Roles decide what each person can do. Disabling keeps the history but blocks sign-in.
          </p>
        </div>
        <Button size="sm" variant="primary" icon="plus" onClick={() => setCreateOpen(true)}>
          Add user
        </Button>
      </div>

      <div className="tg-card overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-border text-2xs uppercase tracking-wide text-faint">
              <th scope="col" className="px-3.5 py-2 font-medium">User</th>
              <th scope="col" className="px-3.5 py-2 font-medium">Role</th>
              <th scope="col" className="px-3.5 py-2 font-medium">Status</th>
              <th scope="col" className="px-3.5 py-2 font-medium">Last sign-in</th>
              <th scope="col" className="px-3.5 py-2 font-medium">Created</th>
              <th scope="col" className="w-10 px-3.5 py-2" />
            </tr>
          </thead>
          <tbody>
            {usersQuery.isLoading ? (
              Array.from({ length: 3 }).map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  <td colSpan={6} className="px-3.5 py-2">
                    <Skeleton className="h-5 w-full" />
                  </td>
                </tr>
              ))
            ) : users.length === 0 ? (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon="shield"
                    title="No users yet"
                    description="This should not happen - the bootstrap administrator is created on first start."
                  />
                </td>
              </tr>
            ) : (
              users.map((u) => {
                const isSelf = u.id === currentUserId
                return (
                  <tr key={u.id} className="border-b border-border/50 last:border-0 hover:bg-surface-2/40">
                    <td className="px-3.5 py-2">
                      <div className="flex items-center gap-2">
                        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border bg-surface-2 text-3xs font-semibold uppercase text-muted">
                          {(u.display_name ?? u.username).slice(0, 2)}
                        </span>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="truncate text-xs text-text">
                              {u.display_name ?? u.username}
                            </span>
                            {isSelf ? (
                              <span className="rounded bg-accent/15 px-1 text-3xs text-accent">you</span>
                            ) : null}
                          </div>
                          <div className="font-mono text-3xs text-faint">{u.username}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-3.5 py-2">
                      <Badge tone={u.role === 'admin' ? 'accent' : u.role === 'operator' ? 'success' : 'neutral'} mono>
                        {u.role}
                      </Badge>
                    </td>
                    <td className="px-3.5 py-2">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 text-2xs',
                          u.is_active ? 'text-success' : 'text-faint',
                        )}
                      >
                        <span
                          aria-hidden="true"
                          className={cn('h-1.5 w-1.5 rounded-full', u.is_active ? 'bg-success' : 'bg-faint')}
                        />
                        {u.is_active ? 'active' : 'disabled'}
                      </span>
                    </td>
                    <td className="px-3.5 py-2 text-2xs text-muted" title={absoluteTime(u.last_login_at)}>
                      {u.last_login_at ? relativeTime(u.last_login_at) : 'never'}
                    </td>
                    <td className="px-3.5 py-2 text-2xs text-muted">{absoluteTime(u.created_at)}</td>
                    <td className="px-3.5 py-2">
                      <ActionMenu
                        label={'Actions for ' + u.username}
                        items={[
                          {
                            label: 'Edit user',
                            icon: 'user',
                            onSelect: () => setEditing(u),
                          },
                          {
                            label: u.is_active ? 'Disable sign-in' : 'Enable sign-in',
                            icon: u.is_active ? 'eye-off' : 'eye',
                            disabled: isSelf,
                            disabledReason: 'You cannot disable your own account.',
                            onSelect: () => toggleActive.mutate(u),
                          },
                          {
                            label: 'Delete user',
                            icon: 'trash',
                            danger: true,
                            disabled: isSelf,
                            disabledReason: 'You cannot delete your own account.',
                            separatorBefore: true,
                            onSelect: () => setRemoving(u),
                          },
                        ]}
                      />
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="rounded border border-border bg-surface-2/50 px-3 py-2.5">
        <div className="flex items-center gap-1.5 text-2xs font-medium text-text">
          <Icon name="info" size={12} className="text-faint" />
          Role reference
        </div>
        <dl className="mt-1.5 space-y-1">
          {(Object.keys(ROLE_HELP) as Role[]).map((role) => (
            <div key={role} className="flex gap-2">
              <dt className="w-16 shrink-0 font-mono text-3xs text-accent">{role}</dt>
              <dd className="text-3xs leading-relaxed text-muted">{ROLE_HELP[role]}</dd>
            </div>
          ))}
        </dl>
      </div>

      <CreateUserModal open={createOpen} onClose={() => setCreateOpen(false)} />
      <EditUserModal user={editing} onClose={() => setEditing(null)} />
      <Modal
        open={removing !== null}
        onClose={() => setRemoving(null)}
        title={'Delete ' + (removing?.username ?? 'user') + '?'}
        description="Their sessions are revoked immediately. Audit history keeps their name."
        size="sm"
        tone="danger"
        footer={
          <>
            <Button onClick={() => setRemoving(null)}>Cancel</Button>
            <Button
              variant="danger"
              icon="trash"
              loading={removeMutation.isPending}
              onClick={() => removing && removeMutation.mutate(removing.id)}
            >
              Delete user
            </Button>
          </>
        }
      >
        <p className="text-2xs leading-relaxed text-muted">
          This only removes their panel account. Tunnels, routers and keys are unaffected.
        </p>
      </Modal>
    </div>
  )
}

function CreateUserModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast()
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [errors, setErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    if (!open) {
      setUsername('')
      setDisplayName('')
      setPassword('')
      setRole('viewer')
      setErrors({})
    }
  }, [open])

  const mutation = useMutation({
    mutationFn: () =>
      api.createUser({
        username: username.trim(),
        password,
        display_name: displayName.trim() || null,
        role,
      }),
    onSuccess: () => {
      toast.success('User created.')
      void queryClient.invalidateQueries({ queryKey: ['users'] })
      void queryClient.invalidateQueries({ queryKey: ['stats'] })
      onClose()
    },
    onError: (err) => {
      const fields = fieldErrors(err)
      if (Object.keys(fields).length > 0) setErrors(fields)
      else toast.error(friendlyMessage(err))
    },
  })

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Add a panel user"
      description="They sign in with the username and password you set here."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            icon="plus"
            loading={mutation.isPending}
            disabled={!username.trim() || password.length < 10}
            onClick={() => mutation.mutate()}
          >
            Create user
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <TextField
          label="Username"
          name="username"
          data-autofocus
          required
          autoComplete="off"
          value={username}
          error={errors.username}
          onChange={(e) => setUsername(e.target.value)}
          hint="Lowercase, no spaces. Used to sign in."
        />
        <TextField
          label="Display name"
          name="display_name"
          value={displayName}
          error={errors.display_name}
          onChange={(e) => setDisplayName(e.target.value)}
          hint="Optional. Shown in the panel and in audit entries."
        />
        <TextField
          label="Initial password"
          name="password"
          type="password"
          required
          autoComplete="new-password"
          value={password}
          error={errors.password}
          onChange={(e) => setPassword(e.target.value)}
          hint="At least 10 characters. Ask them to change it after the first sign-in."
        />
        <SelectField
          label="Role"
          name="role"
          value={role}
          error={errors.role}
          onChange={(e) => setRole(e.target.value as Role)}
          options={[
            { value: 'viewer', label: 'viewer - read only' },
            { value: 'operator', label: 'operator - manage routers' },
            { value: 'admin', label: 'admin - everything' },
          ]}
        />
        <p className="rounded border border-border bg-surface-2 px-2 py-1.5 text-3xs leading-relaxed text-muted">
          {ROLE_HELP[role]}
        </p>
      </div>
    </Modal>
  )
}

function EditUserModal({ user, onClose }: { user: User | null; onClose: () => void }) {
  const toast = useToast()
  const queryClient = useQueryClient()
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [password, setPassword] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({})

  useEffect(() => {
    if (user) {
      setDisplayName(user.display_name ?? '')
      setRole(user.role)
      setPassword('')
      setErrors({})
    }
  }, [user])

  const mutation = useMutation({
    mutationFn: () => {
      if (!user) throw new Error('no user')
      const patch: { display_name: string | null; role: Role; password?: string } = {
        display_name: displayName.trim() || null,
        role,
      }
      if (password.length > 0) patch.password = password
      return api.updateUser(user.id, patch)
    },
    onSuccess: () => {
      toast.success('User updated.')
      void queryClient.invalidateQueries({ queryKey: ['users'] })
      onClose()
    },
    onError: (err) => {
      const fields = fieldErrors(err)
      if (Object.keys(fields).length > 0) setErrors(fields)
      else toast.error(friendlyMessage(err))
    },
  })

  return (
    <Modal
      open={user !== null}
      onClose={onClose}
      title={'Edit ' + (user?.username ?? 'user')}
      description="Changing the role takes effect on their next request."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={mutation.isPending} onClick={() => mutation.mutate()}>
            Save changes
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <TextField
          label="Display name"
          name="edit_display_name"
          value={displayName}
          error={errors.display_name}
          onChange={(e) => setDisplayName(e.target.value)}
        />
        <SelectField
          label="Role"
          name="edit_role"
          value={role}
          error={errors.role}
          onChange={(e) => setRole(e.target.value as Role)}
          options={[
            { value: 'viewer', label: 'viewer - read only' },
            { value: 'operator', label: 'operator - manage routers' },
            { value: 'admin', label: 'admin - everything' },
          ]}
        />
        <p className="rounded border border-border bg-surface-2 px-2 py-1.5 text-3xs leading-relaxed text-muted">
          {ROLE_HELP[role]}
        </p>
        <TextField
          label="Reset password"
          name="edit_password"
          type="password"
          autoComplete="new-password"
          value={password}
          error={errors.password}
          onChange={(e) => setPassword(e.target.value)}
          hint="Leave empty to keep the current password. At least 10 characters."
        />
      </div>
    </Modal>
  )
}

/* --------------------------------------------------------------- panel */
function PanelTab() {
  const configQuery = useQuery({ queryKey: ['config'], queryFn: ({ signal }) => api.config(signal) })
  const statsQuery = useQuery({
    queryKey: ['stats'],
    queryFn: ({ signal }) => api.stats(signal),
    refetchInterval: 15_000,
  })

  const config = configQuery.data
  const stats = statsQuery.data

  if (configQuery.error && !config) {
    return <ErrorState error={configQuery.error} onRetry={() => void configQuery.refetch()} />
  }

  return (
    <div className="max-w-2xl space-y-3 p-4">
      <AgentEndpointCard
        agentUrl={config?.agent_url ?? null}
        endpoint={config?.agent_endpoint ?? null}
        testable={config?.agent_endpoint_testable ?? true}
        loading={configQuery.isLoading}
        reloading={configQuery.isFetching}
        onReload={() => void configQuery.refetch()}
      />

      <section className="tg-card overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-3.5 py-2.5">
          <h2 className="text-xs font-medium text-text">Panel configuration</h2>
          {config ? <Badge tone="neutral" mono>v{config.version}</Badge> : null}
        </div>
        {configQuery.isLoading ? (
          <div className="space-y-2 p-3.5">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-4 w-full" />
            ))}
          </div>
        ) : config ? (
          <ConfigList config={config} />
        ) : null}
      </section>

      <section className="tg-card overflow-hidden">
        <h2 className="border-b border-border px-3.5 py-2.5 text-xs font-medium text-text">Capacity</h2>
        {statsQuery.isLoading ? (
          <div className="grid grid-cols-2 gap-2 p-3.5">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12 w-full" />
            ))}
          </div>
        ) : stats ? (
          <div className="grid grid-cols-2 gap-2 p-3.5">
            <Capacity label="Routers" value={stats.routers_total} hint={stats.routers_online + ' online'} />
            <Capacity label="Free ports" value={stats.ports_free} hint="in the allocation pool" />
            <Capacity label="Users" value={stats.users_total} hint="panel accounts" />
            <Capacity
              label="Open consoles"
              value={stats.console_sessions_active}
              hint="interactive shells right now"
            />
          </div>
        ) : null}
      </section>

      <InlineAlert tone="info" title="The rows below come from the server environment">
        Route mode, gateway host / subdomain suffix, TTL, poll interval, proxy driver and the
        internal panel URL are set with{' '}
        <span className="font-mono">TUNNELGATE_*</span> variables and stay read-only by design - a panel
        compromise must not change how the proxy reaches the panel. The agent endpoint above is the one
        exception: it is what routers dial, and an administrator can override it here.
      </InlineAlert>
    </div>
  )
}

/* ------------------------------------------------- agent endpoint (admin) */

/** Default port for a scheme; null means "the URL has no port to write". */
const DEFAULT_PORTS: Record<AgentScheme, number> = { http: 80, https: 443 }

/** Host text exactly as the server would accept it (the server stays authoritative). */
const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9._-]+$/
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
// Deliberately permissive: the only job here is to catch typos before the round trip.
const IPV6_RE = /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*$/

function parsePort(raw: string): number | null | 'invalid' {
  const t = raw.trim()
  if (t === '') return null
  if (!/^\d{1,5}$/.test(t)) return 'invalid'
  const n = Number(t)
  return n >= 1 && n <= 65535 ? n : 'invalid'
}

function hostError(raw: string): string | null {
  const host = raw.trim()
  if (!host) return 'Enter the host routers should dial.'
  if (host.includes('://')) return 'Enter a host only, without the protocol.'
  if (/[\s/]/.test(host)) return 'A host cannot contain spaces, a path or a trailing slash.'
  if (host.includes('@')) return 'A host cannot contain credentials.'
  if (host.length > 253) return 'A host cannot be longer than 253 characters.'
  if (host.startsWith('[')) {
    if (!/^\[[^\]]+\]$/.test(host)) return 'Close the IPv6 address with a bracket.'
    return IPV6_RE.test(host.slice(1, -1)) ? null : 'That is not a valid IPv6 address.'
  }
  if (host.includes(':') && !IPV6_RE.test(host)) return 'That is not a valid IPv6 address.'
  if (/[;'"\\<>?#%]/.test(host)) return 'That is not a valid hostname.'
  if (!HOST_RE.test(host) && !IPV6_RE.test(host)) return 'Use a DNS name, an IPv4 or an IPv6 address.'
  if (/^\d/.test(host) && host.includes('.') && !IPV4_RE.test(host) && !/[A-Za-z]/.test(host)) {
    return 'That looks like an IPv4 address, but the octets are out of range.'
  }
  if (/^\.|\.$/.test(host)) return 'A host cannot start or end with a dot.'
  return null
}

/** Renders the URL the routers would dial, mirroring the server's serialisation. */
function agentUrl(scheme: AgentScheme, host: string, port: number | null): string {
  const clean = host.trim()
  const shown = clean.includes(':') && !clean.startsWith('[') ? `[${clean}]` : clean
  return `${scheme}://${shown}${port !== null && port !== DEFAULT_PORTS[scheme] ? `:${port}` : ''}`
}

/** "set in panel" vs "from environment", as a badge next to the card title. */
function SourceBadge({ source }: { source: 'environment' | 'database' }) {
  return source === 'database' ? (
    <Badge tone="accent">set in panel</Badge>
  ) : (
    <Badge tone="neutral">from environment</Badge>
  )
}

function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn('break-all font-mono', className)}>{children}</span>
}

function AgentEndpointCard({
  agentUrl: currentUrl,
  endpoint,
  testable,
  loading,
  reloading,
  onReload,
}: {
  agentUrl: string | null
  endpoint: PanelConfig['agent_endpoint'] | null
  /** The server can refuse to probe (no hostname at all), in which case the button stays off. */
  testable: boolean
  loading: boolean
  reloading: boolean
  onReload: () => void
}) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const toast = useToast()
  const queryClient = useQueryClient()

  const [scheme, setScheme] = useState<AgentScheme>(endpoint?.scheme ?? 'https')
  const [host, setHost] = useState(endpoint?.host ?? '')
  const [port, setPort] = useState(endpoint?.port === null || endpoint?.port === undefined ? '' : String(endpoint.port))
  const [fieldError, setFieldError] = useState<Record<string, string>>({})
  const [savedUrl, setSavedUrl] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<AgentEndpointTest | null>(null)
  const [confirmReset, setConfirmReset] = useState(false)

  // Seeds from the server every time the effective endpoint identity changes, so a
  // save/revert elsewhere (or a reload) resets the form instead of stranding edits.
  const seededRef = useRef<string>('')
  const seedKey = endpoint ? `${endpoint.source}:${endpoint.scheme}:${endpoint.host}:${endpoint.port}` : ''
  useEffect(() => {
    if (!endpoint || seededRef.current === seedKey) return
    seededRef.current = seedKey
    setScheme(endpoint.scheme)
    setHost(endpoint.host)
    setPort(endpoint.port === null ? '' : String(endpoint.port))
    setFieldError({})
    setSavedUrl(null)
    setTestResult(null)
  }, [endpoint, seedKey])

  const parsedPort = parsePort(port)
  const portProblem = parsedPort === 'invalid' ? 'Use a port between 1 and 65535, or leave it empty.' : null
  const hostProblem = host.trim() ? hostError(host) : null
  const invalid = Boolean(fieldError.host || fieldError.port || hostProblem || portProblem || !host.trim())
  const previewUrl =
    host.trim() && !hostProblem && !portProblem
      ? agentUrl(scheme, host, parsedPort === 'invalid' ? null : parsedPort)
      : null

  const pristine =
    endpoint !== null &&
    scheme === endpoint.scheme &&
    host.trim() === endpoint.host &&
    (parsedPort === 'invalid' ? null : parsedPort) === endpoint.port

  const payload = (): AgentEndpointInput => ({
    scheme,
    host: host.trim(),
    port: parsedPort === 'invalid' ? null : parsedPort,
  })

  const applyResult = (res: AgentEndpointResult) => {
    queryClient.setQueryData<PanelConfig>(['config'], (old) =>
      old ? { ...old, agent_url: res.agent_url, agent_endpoint: res.agent_endpoint } : old,
    )
    seededRef.current = `${res.agent_endpoint.source}:${res.agent_endpoint.scheme}:${res.agent_endpoint.host}:${res.agent_endpoint.port}`
    setScheme(res.agent_endpoint.scheme)
    setHost(res.agent_endpoint.host)
    setPort(res.agent_endpoint.port === null ? '' : String(res.agent_endpoint.port))
    setFieldError({})
    // Only a database override is a save; after a revert the badge would lie.
    setSavedUrl(res.agent_endpoint.source === 'database' ? res.agent_url : null)
    setTestResult(null)
    void queryClient.invalidateQueries({ queryKey: ['config'] })
  }

  const saveMutation = useMutation({
    mutationFn: () => api.agentEndpointSave(payload()),
    onSuccess: (res) => {
      applyResult(res)
      toast.success('Agent endpoint saved')
    },
    onError: (err) => {
      const fields = fieldErrors(err)
      // The server owns validation: it can report host or port, never the scheme.
      if (Object.keys(fields).length > 0) setFieldError(fields)
      else toast.error(friendlyMessage(err))
    },
  })

  const resetMutation = useMutation({
    mutationFn: () => api.agentEndpointReset(),
    onSuccess: (res) => {
      applyResult(res)
      setConfirmReset(false)
      toast.success('Agent endpoint reverted to the environment value')
    },
    onError: (err) => {
      setConfirmReset(false)
      toast.error(friendlyMessage(err))
    },
  })

  const testMutation = useMutation({
    mutationFn: () => api.agentEndpointTest(payload()),
    onSuccess: (res) => setTestResult(res),
    onError: (err) =>
      setTestResult({
        ok: false,
        checked_url: previewUrl ?? '',
        status_code: null,
        latency_ms: null,
        error: friendlyMessage(err),
      }),
  })

  const header = (
    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3.5 py-2.5">
      <div className="flex items-center gap-2">
        <h2 className="text-xs font-medium text-text">Agent endpoint</h2>
        {endpoint ? <SourceBadge source={endpoint.source} /> : null}
      </div>
      {currentUrl ? <Mono className="text-3xs text-muted">{currentUrl}</Mono> : null}
    </div>
  )

  const copy = (
    <p className="mt-0.5 max-w-prose text-2xs leading-relaxed text-muted">
      The protocol, host and port routers dial. Every install command, the installer's heartbeat URL
      and the URLs baked into an installation script use this address. The proxy keeps using the
      internal panel URL.
    </p>
  )

  if (loading) {
    return (
      <section className="tg-card overflow-hidden">
        {header}
        <div className="space-y-2 p-3.5">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </div>
      </section>
    )
  }

  // The panel can report no usable endpoint at all (TUNNELGATE_PANEL_URL is not a valid
  // http(s) URL and nothing is stored). An admin must still be able to fix it from here - the
  // backend's own error text says "set the endpoint here instead" - so the form renders empty.
  const missing = (
    <InlineAlert
      tone="warning"
      className="mt-3"
      title={isAdmin ? 'The panel has no usable agent endpoint yet' : 'No agent endpoint is configured'}
    >
      {isAdmin
        ? 'TUNNELGATE_PANEL_URL is not a valid http(s) URL and no override is stored, so no install command can point anywhere. Set the protocol, host and port below.'
        : 'Routers cannot be installed until an administrator sets the address they dial.'}
    </InlineAlert>
  )

  if (!isAdmin) {
    return (
      <section className="tg-card overflow-hidden">
        {header}
        <div className="p-3.5">
          {copy}
          {endpoint ? (
            <dl className="mt-3 divide-y divide-border/60 rounded border border-border">
              {[
                ['Protocol', endpoint.scheme],
                ['Host', endpoint.host],
                [
                  'Port',
                  endpoint.port === null
                    ? `${DEFAULT_PORTS[endpoint.scheme]} (scheme default)`
                    : String(endpoint.port),
                ],
              ].map(([label, value]) => (
                <div key={label} className="flex items-start gap-3 px-3 py-1.5">
                  <dt className="w-24 shrink-0 text-2xs text-muted">{label}</dt>
                  <dd className="min-w-0 flex-1 break-all font-mono text-2xs text-text">{value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
          {missing}
          <InlineAlert tone="info" className="mt-3" title="Only an admin can change where routers dial">
            Ask an administrator if this address is wrong - every pending install command points at it.
          </InlineAlert>
        </div>
      </section>
    )
  }

  return (
    <section className="tg-card overflow-hidden">
      {header}
      <form
        className="p-3.5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          setFieldError({})
          if (!host.trim() || hostProblem) return
          if (portProblem) return
          saveMutation.mutate()
        }}
      >
        {copy}
        {!endpoint ? missing : null}

        <div className="mt-3 flex flex-wrap items-start gap-2.5">
          <SelectField
            label="Protocol"
            name="agent_scheme"
            markOptional={false}
            className="w-28"
            value={scheme}
            disabled={saveMutation.isPending}
            onChange={(e) => {
              setScheme(e.target.value as AgentScheme)
              setTestResult(null)
            }}
            options={[
              { value: 'https', label: 'https' },
              { value: 'http', label: 'http' },
            ]}
          />
          <TextField
            label="Host"
            name="agent_host"
            markOptional={false}
            className="min-w-[14rem] flex-1"
            placeholder="gate.example.com"
            autoCapitalize="none"
            autoComplete="off"
            spellCheck={false}
            value={host}
            error={fieldError.host || hostProblem || null}
            disabled={saveMutation.isPending}
            onChange={(e) => {
              setHost(e.target.value)
              setFieldError((f) => ({ ...f, host: '' }))
              setTestResult(null)
            }}
          />
          <TextField
            label="Port"
            name="agent_port"
            className="w-32"
            inputMode="numeric"
            placeholder="443"
            autoComplete="off"
            value={port}
            hint="Leave empty for the default (80/443)"
            error={fieldError.port || portProblem || null}
            disabled={saveMutation.isPending}
            onChange={(e) => {
              setPort(e.target.value.replace(/[^0-9]/g, ''))
              setFieldError((f) => ({ ...f, port: '' }))
              setTestResult(null)
            }}
          />
        </div>

        {previewUrl ? (
          <p className="mt-2.5 text-2xs text-muted">
            Routers will dial:{' '}
            <Mono className="text-text" >{previewUrl}</Mono>
            {savedUrl && savedUrl === previewUrl ? (
              <span className="ml-1.5 text-3xs text-success">· saved</span>
            ) : null}
          </p>
        ) : null}

        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border pt-3">
          <Button
            type="submit"
            size="sm"
            variant="primary"
            loading={saveMutation.isPending}
            disabled={pristine || invalid}
          >
            {saveMutation.isPending ? 'Saving…' : 'Save'}
          </Button>
          <Button
            size="sm"
            variant="secondary"
            icon="activity"
            loading={testMutation.isPending}
            disabled={
              !testable ||
              !host.trim() ||
              Boolean(hostProblem) ||
              Boolean(portProblem) ||
              testMutation.isPending
            }
            title={testable ? undefined : 'The panel has no address of its own to probe from'}
            onClick={() => testMutation.mutate()}
          >
            Test connection
          </Button>
          {endpoint?.source === 'database' ? (
            <Button
              size="sm"
              variant="ghost"
              icon="refresh"
              disabled={resetMutation.isPending}
              onClick={() => setConfirmReset(true)}
            >
              Use environment default
            </Button>
          ) : null}
          {reloading ? (
            <span className="ml-auto flex items-center gap-1.5 text-3xs text-faint">
              <Icon name="spinner" size={11} className="animate-spin" />
              refreshing
            </span>
          ) : (
            <Button size="sm" variant="ghost" icon="refresh" className="ml-auto" onClick={onReload}>
              Reload
            </Button>
          )}
        </div>

        <AgentEndpointTestResult result={testResult} testing={testMutation.isPending} />
      </form>

      <ConfirmDialog
        open={confirmReset}
        onClose={() => setConfirmReset(false)}
        onConfirm={() => resetMutation.mutate()}
        title="Revert to the environment default?"
        description="The endpoint you saved in the panel is removed."
        confirmLabel="Use environment default"
        loading={resetMutation.isPending}
      >
        <p className="text-2xs leading-relaxed text-muted">
          Routers will dial the address the server was started with, and the next install command will
          contain it instead of <Mono className="text-text">{currentUrl ?? ''}</Mono>. Existing tunnels are
          not touched.
        </p>
      </ConfirmDialog>
    </section>
  )
}

/** Inline (never toasted) result of the reachability probe, announced politely. */
function AgentEndpointTestResult({
  result,
  testing,
}: {
  result: AgentEndpointTest | null
  testing: boolean
}) {
  const live = testing || result !== null
  return (
    <div aria-live="polite" role="status" className={cn('mt-2.5', !live && 'sr-only')}>
      {testing ? (
        <p className="flex items-center gap-1.5 text-2xs text-muted">
          <Icon name="spinner" size={12} className="animate-spin" />
          Checking the endpoint…
        </p>
      ) : result ? (
        <div
          className={cn(
            'rounded border px-2.5 py-2 text-2xs',
            result.ok ? 'border-success/35 bg-success/[0.07] text-success' : 'border-danger/35 bg-danger/[0.07] text-danger',
          )}
        >
          <div className="flex items-start gap-1.5">
            <Icon name={result.ok ? 'check-circle' : 'alert'} size={13} className="mt-px shrink-0" />
            <div className="min-w-0">
              <div className="font-medium">
                {result.ok
                  ? `Reachable: HTTP ${result.status_code ?? '?'} in ${result.latency_ms ?? '?'} ms`
                  : `Not reachable: ${result.error ?? 'the panel could not reach that address.'}`}
              </div>
              <div className="mt-0.5 break-all text-3xs opacity-80">
                Checked <Mono>{result.checked_url}</Mono>
                {result.latency_ms !== null && !result.ok ? ` in ${result.latency_ms} ms` : null}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}

function ConfigList({ config }: { config: PanelConfig }) {
  const pathMode = config.route_mode === 'path'
  const rows: Array<[string, string, string | null]> = [
    ['Agent URL', config.agent_url, 'What routers dial (editable above).'],
    ['Internal panel URL', config.panel_url, 'How the proxy reaches the panel on this host.'],
    ['Route mode', config.route_mode, pathMode ? 'One gateway host, and a path per router.' : 'One host per router.'],
    ...(pathMode
      ? ([
          [
            'Gateway host',
            config.gateway_host,
            'Every router is published as <gateway>/<slug>/.',
          ],
        ] as Array<[string, string, string | null]>)
      : ([
          [
            'Subdomain suffix',
            config.subdomain_suffix,
            'Per-router hostnames are <slug>.<suffix>.',
          ],
        ] as Array<[string, string, string | null]>)),
    [
      'Bootstrap TTL',
      config.bootstrap_ttl_minutes + ' min',
      'How long an install command stays valid.',
    ],
    [
      'Poll interval',
      config.poll_interval_seconds + ' s',
      'How often the wizard and status views re-check.',
    ],
    ['Proxy driver', config.proxy_driver, 'Component that writes per-router vhosts.'],
    ['Version', config.version, null],
  ]

  return (
    <dl className="divide-y divide-border/60">
      {rows.map(([label, value, hint]) => (
        <div key={label} className="flex items-start gap-3 px-3.5 py-2">
          <dt className="w-36 shrink-0 pt-0.5 text-2xs text-muted">{label}</dt>
          <dd className="min-w-0 flex-1">
            {value ? (
              <div className="break-all font-mono text-2xs text-text">{value}</div>
            ) : (
              <div className="font-mono text-2xs text-faint">not set</div>
            )}
            {hint ? <div className="mt-0.5 text-3xs leading-relaxed text-faint">{hint}</div> : null}
          </dd>
        </div>
      ))}
    </dl>
  )
}

function Capacity({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <div className="rounded border border-border bg-surface-2 px-2.5 py-2">
      <div className="text-3xs uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-0.5 font-mono text-sm tabular-nums text-text">{value}</div>
      <div className="mt-0.5 text-3xs text-faint">{hint}</div>
    </div>
  )
}