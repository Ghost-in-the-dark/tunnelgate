import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, fieldErrors, friendlyMessage } from '../lib/api'
import type { PanelConfig, Role, User } from '../lib/types'
import { useAuth, useLocalStorage } from '../lib/hooks'
import { cn } from '../lib/cn'
import { absoluteTime, relativeTime } from '../lib/format'
import { TopBar } from '../components/AppShell'
import { Badge } from '../components/Badge'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { SelectField, TextField } from '../components/Field'
import { ActionMenu } from '../components/Menu'
import { Modal } from '../components/Modal'
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

      <InlineAlert tone="info" title="These values come from the server environment">
        They are set with <span className="font-mono">TUNNELGATE_*</span> variables and are read-only here by
        design - a panel compromise must not be able to change how the proxy talks to the outside world.
      </InlineAlert>
    </div>
  )
}

function ConfigList({ config }: { config: PanelConfig }) {
  const rows: Array<[string, string, string | null]> = [
    ['Panel URL', config.panel_url, 'Where routers and users reach this panel.'],
    ['Subdomain suffix', config.subdomain_suffix, 'Per-router hostnames are <slug>.<suffix>.'],
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
            <div className="break-all font-mono text-2xs text-text">{value}</div>
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