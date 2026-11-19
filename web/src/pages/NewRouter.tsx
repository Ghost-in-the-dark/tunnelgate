import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { ApiError, api, fieldErrors, friendlyMessage } from '../lib/api'
import type { RouterCreated, RouterStatus } from '../lib/types'
import { useCountdown } from '../lib/hooks'
import { cn } from '../lib/cn'
import { copyText } from '../lib/clipboard'
import { clockDuration, slugify } from '../lib/format'
import { Button } from '../components/Button'
import { Icon } from '../components/Icon'
import { TextField, TextAreaField } from '../components/Field'
import { Stepper, VerticalStepper } from '../components/Stepper'
import { InlineAlert, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import {
  COMMAND_VARIANTS,
  EMPTY_DRAFT,
  OS_OPTIONS,
  PHASE_META,
  PHASES,
  SUGGESTED_INTEGRATIONS,
  TROUBLESHOOTING,
  WIZARD_STEPS,
  commandFor,
} from '../lib/install'
import type { CommandVariant, WizardDraft } from '../lib/install'

type CreatedState = Pick<RouterCreated, 'id' | 'install_command' | 'install_script_url' | 'bootstrap_expires_at'> & {
  name?: string
}

const STEP_QUERY = 'step'
const ID_QUERY = 'id'

export function NewRouterPage() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()

  const step = clamp(Number(params.get(STEP_QUERY) ?? 1), 1, 4)
  const routerId = params.get(ID_QUERY)

  /** The token-bearing command. Never persisted: a reload must not resurrect it. */
  const [created, setCreated] = useState<CreatedState | null>(null)
  const [draft, setDraft] = useState<WizardDraft>(EMPTY_DRAFT)
  const [draftErrors, setDraftErrors] = useState<Record<string, string>>({})
  const [createError, setCreateError] = useState<string | null>(null)
  const [maxReached, setMaxReached] = useState(step)

  useEffect(() => {
    setMaxReached((m) => Math.max(m, step))
  }, [step])

  // A router id in the URL without a command in memory means the user reloaded on
  // step 3/4. The token is unrecoverable by design; the ID is kept so step 4 can still poll.
  const needsRotation = (step === 3 || step === 4) && routerId !== null && created === null

  const goToStep = useCallback(
    (next: number) => {
      const p = new URLSearchParams(params)
      p.set(STEP_QUERY, String(next))
      if (routerId) p.set(ID_QUERY, routerId)
      setParams(p, { replace: false })
    },
    [params, routerId, setParams],
  )

  const createMutation = useMutation({
    mutationFn: (input: Parameters<typeof api.createRouter>[0]) => api.createRouter(input),
    onSuccess: (data) => {
      setCreated({
        id: data.id,
        install_command: data.install_command,
        install_script_url: data.install_script_url,
        bootstrap_expires_at: data.bootstrap_expires_at,
        name: data.name,
      })
      const p = new URLSearchParams()
      p.set(STEP_QUERY, '3')
      p.set(ID_QUERY, data.id)
      setParams(p, { replace: true })
      setMaxReached(4)
    },
    onError: (err) => {
      const fields = fieldErrors(err)
      if (Object.keys(fields).length > 0) setDraftErrors(fields)
      else setCreateError(friendlyMessage(err))
    },
  })

  const rotateMutation = useMutation({
    mutationFn: (id: string) => api.rotateKey(id),
    onSuccess: (data) => {
      setCreated({
        id: routerId!,
        install_command: data.install_command,
        install_script_url: data.install_script_url,
        bootstrap_expires_at: data.bootstrap_expires_at,
      })
      toast.success('New install command generated. The previous one no longer works.')
    },
    onError: (err) => toast.error(friendlyMessage(err)),
  })

  const submitStep2 = () => {
    const errors: Record<string, string> = {}
    const name = draft.name.trim()
    if (!name) errors.name = 'A friendly name is required - it is what operators see first.'
    else if (name.length > 128) errors.name = 'Keep the name under 128 characters.'
    if (draft.http_port < 1 || draft.http_port > 65535) errors.http_port = 'Port must be between 1 and 65535.'
    setDraftErrors(errors)
    if (Object.keys(errors).length > 0) return

    setCreateError(null)
    createMutation.mutate({
      name,
      slug: slugify(name) || null,
      group_name: draft.group_name.trim() || null,
      integrations: draft.integrations,
      os_type: draft.os_type,
      notes: draft.notes.trim() || null,
      http_port: draft.http_port,
    })
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-surface/40 px-4">
        <button
          type="button"
          onClick={() => navigate('/hosts')}
          className="flex items-center gap-1 text-xs text-muted transition-colors hover:text-text"
        >
          <Icon name="chevron-left" size={13} />
          Hosts
        </button>
        <span aria-hidden="true" className="text-border-strong">
          /
        </span>
        <h1 className="text-sm font-medium text-text">Add router</h1>
        <div className="ml-auto hidden md:block">
          <Stepper
            steps={WIZARD_STEPS}
            current={step}
            maxReached={needsRotation ? 2 : maxReached}
            onStepClick={(s) => goToStep(s)}
          />
        </div>
      </header>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-3xl px-4 py-6">
          <div className="mb-5 md:hidden">
            <Stepper
              steps={WIZARD_STEPS}
              current={step}
              maxReached={needsRotation ? 2 : maxReached}
              onStepClick={(s) => goToStep(s)}
            />
          </div>

          {step === 1 ? (
            <StepChooseOs
              draft={draft}
              onChange={(os) => setDraft((d) => ({ ...d, os_type: os }))}
              onNext={() => goToStep(2)}
            />
          ) : null}

          {step === 2 ? (
            <StepDetails
              draft={draft}
              onChange={(patch) => setDraft((d) => ({ ...d, ...patch }))}
              errors={draftErrors}
              error={createError}
              submitting={createMutation.isPending}
              onBack={() => goToStep(1)}
              onNext={submitStep2}
            />
          ) : null}

          {step === 3 ? (
            needsRotation ? (
              <StepNeedsRotation
                routerId={routerId!}
                rotating={rotateMutation.isPending}
                onRotate={() => rotateMutation.mutate(routerId!)}
                onBack={() => goToStep(2)}
                onOpenDetail={() => navigate(`/routers/${encodeURIComponent(routerId!)}`)}
              />
            ) : created ? (
              <StepCommand
                created={created}
                onBack={() => goToStep(2)}
                onNext={() => goToStep(4)}
              />
            ) : (
              <InlineAlert tone="warning" title="No install command in this session">
                Create the router again to generate one.
                <Button className="mt-2" size="sm" onClick={() => goToStep(2)}>
                  Back to details
                </Button>
              </InlineAlert>
            )
          ) : null}

          {step === 4 ? (
            needsRotation ? (
              <StepNeedsRotation
                routerId={routerId!}
                rotating={rotateMutation.isPending}
                onRotate={() => rotateMutation.mutate(routerId!)}
                onBack={() => goToStep(2)}
                onOpenDetail={() => navigate(`/routers/${encodeURIComponent(routerId!)}`)}
              />
            ) : (
              <StepConnection
                routerId={routerId ?? created?.id ?? null}
                routerName={created?.name ?? 'router'}
                onBack={() => goToStep(3)}
                onDone={(id) => navigate(`/routers/${encodeURIComponent(id)}`, { replace: true })}
              />
            )
          ) : null}
        </div>
      </div>
    </div>
  )
}

function clamp(n: number, min: number, max: number): number {
  if (Number.isNaN(n)) return min
  return Math.max(min, Math.min(max, n))
}

/* ------------------------------------------------------------------ step 1 */
function StepChooseOs({
  draft,
  onChange,
  onNext,
}: {
  draft: WizardDraft
  onChange: (os: WizardDraft['os_type']) => void
  onNext: () => void
}) {
  return (
    <section aria-labelledby="step1-title">
      <h2 id="step1-title" className="text-sm font-semibold text-text">
        What is the router running?
      </h2>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        The installer is the same POSIX shell script for every platform; the choice here tunes
        supervision and the paths the script writes.
      </p>

      <div className="mt-4 grid gap-2.5 sm:grid-cols-3" role="radiogroup" aria-labelledby="step1-title">
        {OS_OPTIONS.map((os) => {
          const selected = draft.os_type === os.id
          return (
            <button
              key={os.id}
              type="button"
              role="radio"
              aria-checked={selected}
              onClick={() => onChange(os.id)}
              className={cn(
                'relative flex flex-col items-start gap-2 rounded-lg border p-3.5 text-left transition-colors',
                selected
                  ? 'border-accent bg-accent/[0.06] ring-1 ring-accent/40'
                  : 'border-border bg-surface hover:border-border-strong hover:bg-surface-2/50',
              )}
            >
              <div className="flex w-full items-center justify-between">
                <span
                  className={cn(
                    'flex h-8 w-8 items-center justify-center rounded border',
                    selected ? 'border-accent/40 bg-accent/12 text-accent' : 'border-border bg-surface-2 text-muted',
                  )}
                >
                  <Icon name={os.icon} size={16} />
                </span>
                <span
                  className={cn(
                    'flex h-4 w-4 items-center justify-center rounded-full border',
                    selected ? 'border-accent bg-accent text-white' : 'border-border-strong',
                  )}
                  aria-hidden="true"
                >
                  {selected ? <Icon name="check" size={10} /> : null}
                </span>
              </div>
              <div>
                <div className="text-xs font-semibold text-text">{os.label}</div>
                <div className="mt-0.5 text-3xs text-muted">{os.blurb}</div>
              </div>
              <p className="text-2xs leading-relaxed text-faint">{os.detail}</p>
              {!os.supported ? (
                <span className="mt-auto rounded-sm border border-warning/30 bg-warning/10 px-1.5 py-0.5 text-3xs text-warning">
                  best effort
                </span>
              ) : null}
            </button>
          )
        })}
      </div>

      {draft.os_type === 'windows' ? (
        <InlineAlert tone="warning" className="mt-3" title="Windows is best effort">
          There is no native service supervisor yet. Run the command from a POSIX shell and keep it
          alive with a scheduled task; the panel will only see the tunnel while that task runs.
        </InlineAlert>
      ) : null}

      <div className="mt-5 flex justify-end">
        <Button variant="primary" iconRight="arrow-right" onClick={onNext}>
          Continue
        </Button>
      </div>
    </section>
  )
}

/* ------------------------------------------------------------------ step 2 */
function StepDetails({
  draft,
  onChange,
  errors,
  error,
  submitting,
  onBack,
  onNext,
}: {
  draft: WizardDraft
  onChange: (patch: Partial<WizardDraft>) => void
  errors: Record<string, string>
  error: string | null
  submitting: boolean
  onBack: () => void
  onNext: () => void
}) {
  const [integrationDraft, setIntegrationDraft] = useState('')
  const nameRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    nameRef.current?.focus()
  }, [])

  const addIntegration = (value: string) => {
    const v = value.trim()
    if (!v) return
    if (draft.integrations.includes(v)) return
    onChange({ integrations: [...draft.integrations, v] })
    setIntegrationDraft('')
  }

  return (
    <section aria-labelledby="step2-title">
      <h2 id="step2-title" className="text-sm font-semibold text-text">
        Router details
      </h2>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        Only the name is required. Grouping and integrations are optional and can be changed later.
      </p>

      <form
        className="mt-4 space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          onNext()
        }}
        noValidate
      >
        {error ? (
          <InlineAlert tone="danger" title="Could not create the router">
            {error}
          </InlineAlert>
        ) : null}

        <TextField
          ref={nameRef}
          label="Friendly Name"
          name="name"
          required
          value={draft.name}
          maxLength={128}
          onChange={(e) => onChange({ name: e.target.value })}
          error={errors.name}
          hint={
            draft.name.trim() ? (
              <>
                Appears in the host list. URL slug:{' '}
                <code className="rounded bg-surface-3 px-1 font-mono text-text">{slugify(draft.name) || '—'}</code>
              </>
            ) : (
              'How you will recognise this router, e.g. "Office Berlin - entrance".'
            )
          }
          placeholder="Office Berlin - entrance"
        />

        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            label="Group"
            name="group_name"
            list="tg-groups"
            value={draft.group_name}
            maxLength={64}
            onChange={(e) => onChange({ group_name: e.target.value })}
            hint="Optional. Groups are free-form; typing an existing one reuses it."
            placeholder="branch-office"
          />
          {/* Existing groups are only known client-side from the host list, which is fine
              for a datalist - the server accepts any string. */}
          <datalist id="tg-groups">
            {['branch-office', 'datacenter', 'lab', 'staging'].map((g) => (
              <option key={g} value={g} />
            ))}
          </datalist>

          <TextField
            label="LuCI HTTP port"
            name="http_port"
            type="number"
            min={1}
            max={65535}
            value={String(draft.http_port)}
            onChange={(e) => onChange({ http_port: Number(e.target.value) || 80 })}
            error={errors.http_port}
            hint="The port LuCI listens on, on the router itself. 80 unless you changed it."
          />
        </div>

        <fieldset>
          <legend className="tg-label mb-1.5">Integrations</legend>
          <div className="flex flex-wrap items-center gap-1.5 rounded border border-border bg-surface-2 p-2">
            {draft.integrations.length === 0 ? (
              <span className="px-1 text-2xs text-faint">None selected</span>
            ) : null}
            {draft.integrations.map((it) => (
              <span
                key={it}
                className="inline-flex items-center gap-1 rounded-sm border border-accent/35 bg-accent/10 py-0.5 pl-1.5 pr-1 text-2xs text-accent"
              >
                <span className="font-mono">{it}</span>
                <button
                  type="button"
                  onClick={() => onChange({ integrations: draft.integrations.filter((x) => x !== it) })}
                  aria-label={`Remove integration ${it}`}
                  className="rounded p-0.5 hover:bg-accent/20"
                >
                  <Icon name="x" size={10} />
                </button>
              </span>
            ))}
            <input
              value={integrationDraft}
              onChange={(e) => setIntegrationDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ',') {
                  e.preventDefault()
                  addIntegration(integrationDraft)
                } else if (e.key === 'Backspace' && !integrationDraft && draft.integrations.length > 0) {
                  onChange({ integrations: draft.integrations.slice(0, -1) })
                }
              }}
              onBlur={() => addIntegration(integrationDraft)}
              placeholder="add and press Enter"
              aria-label="Add an integration tag"
              className="h-6 min-w-[8rem] flex-1 bg-transparent px-1 text-2xs text-text placeholder:text-faint focus:outline-none"
            />
          </div>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {SUGGESTED_INTEGRATIONS.filter((s) => !draft.integrations.includes(s)).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => addIntegration(s)}
                className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-3xs text-muted transition-colors hover:border-accent/40 hover:text-accent"
              >
                + {s}
              </button>
            ))}
          </div>
        </fieldset>

        <TextAreaField
          label="Notes"
          name="notes"
          value={draft.notes}
          onChange={(e) => onChange({ notes: e.target.value })}
          placeholder="Rack 4, uplink via LTE, contact: network team"
          rows={2}
        />

        <div className="flex items-center justify-between pt-1">
          <Button onClick={onBack} icon="chevron-left" disabled={submitting}>
            Back
          </Button>
          <Button type="submit" variant="primary" loading={submitting} iconRight="arrow-right">
            {submitting ? 'Creating…' : 'Create and show command'}
          </Button>
        </div>
      </form>
    </section>
  )
}

/* ------------------------------------------------------------------ step 3 */
function StepCommand({
  created,
  onBack,
  onNext,
}: {
  created: CreatedState
  onBack: () => void
  onNext: () => void
}) {
  const [variant, setVariant] = useState<CommandVariant['id']>('install')
  const [copied, setCopied] = useState(false)
  const { secondsLeft } = useCountdown(created.bootstrap_expires_at)
  const toast = useToast()

  const command = useMemo(
    () => commandFor(variant, created.install_command, created.install_script_url),
    [variant, created],
  )

  const copy = async () => {
    const ok = await copyText(command)
    if (ok) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } else {
      toast.error('The browser refused clipboard access. Select the text and copy it manually.')
    }
  }

  const expired = secondsLeft !== null && secondsLeft <= 0

  return (
    <section aria-labelledby="step3-title">
      <h2 id="step3-title" className="text-sm font-semibold text-text">
        Run this on the router
      </h2>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        Paste the command into the router&apos;s shell (SSH or LuCI → System → Terminal). It installs
        the agent, exchanges its key once and starts the tunnel.
      </p>
      <p className="mt-2 text-xs leading-relaxed text-muted">
        It runs on a stock OpenWrt image with no extra packages. The command picks whichever
        fetcher the router has and tells you if it has neither - you do not need curl.
      </p>

      <InlineAlert tone="warning" className="mt-3" title="This command is shown only once">
        <p>
          It contains a single-use bootstrap token that is stored on the server as a SHA-256 hash - it
          cannot be displayed again. It contains no private key and no port number. If you lose it,
          rotate the key to mint a new one.
        </p>
        <p className="mt-2">
          The token travels in the URL rather than in a header, because the router&apos;s fetcher has to
          work on every OpenWrt release and older ones cannot send one. So it is also kept in the
          router&apos;s shell history (
          <span className="font-mono text-text">~/.ash_history</span>) and shows up in
          <span className="font-mono text-text"> ps</span> while the command runs - acceptable only
          because the token is single-use and expires in minutes. On a shared router, delete that line
          from the history file afterwards.
        </p>
      </InlineAlert>

      <div className="mt-4 overflow-hidden rounded-lg border border-border bg-surface">
        <div className="flex items-center justify-between gap-2 border-b border-border bg-surface-2/60 px-2 py-1.5">
          <div className="flex gap-0.5" role="tablist" aria-label="Command variant">
            {COMMAND_VARIANTS.map((v) => (
              <button
                key={v.id}
                role="tab"
                type="button"
                aria-selected={variant === v.id}
                onClick={() => setVariant(v.id)}
                className={cn(
                  'rounded-sm px-2 py-1 font-mono text-2xs transition-colors',
                  variant === v.id ? 'bg-surface-3 text-text' : 'text-muted hover:text-text',
                )}
              >
                {v.label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2">
            {secondsLeft !== null ? (
              <span
                className={cn(
                  'flex items-center gap-1 font-mono text-2xs tabular-nums',
                  expired ? 'text-danger' : secondsLeft < 120 ? 'text-warning' : 'text-muted',
                )}
              >
                <Icon name="clock" size={11} />
                {expired ? 'expired' : `expires in ${clockDuration(secondsLeft)}`}
              </span>
            ) : null}
            <Button size="sm" variant={copied ? 'secondary' : 'subtle'} icon={copied ? 'check' : 'copy'} onClick={copy}>
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
        </div>

        <pre className="overflow-x-auto p-3 font-mono text-2xs leading-relaxed text-text">
          <code>{command}</code>
        </pre>
      </div>

      {expired ? (
        <InlineAlert tone="danger" className="mt-3" title="This token has expired">
          Go back and rotate the key to generate a fresh command; the old one will be rejected.
        </InlineAlert>
      ) : null}

      {variant === 'manual' ? (
        <p className="mt-2 text-2xs leading-relaxed text-muted">
          This URL carries no token, so it can be pasted or logged safely - on its own it will not
          install anything. Use it when you want to download the script on a machine that is not the
          router; without the one-time token from the command above the panel refuses the request.
        </p>
      ) : (
        <p className="mt-2 text-2xs leading-relaxed text-muted">
          Run the whole block, not just the first line: it downloads the script to a temporary file,
          checks that the panel really returned the installer, and only then runs it. A rejected token
          answers with an empty body, which is why nothing is piped straight into a shell.
        </p>
      )}

      <ol className="mt-4 space-y-1.5 rounded border border-border bg-surface/50 p-3 text-2xs leading-relaxed text-muted">
        <li className="flex gap-2">
          <span className="font-mono text-faint">1.</span> The script stores its API token and private key
          on the router only - the private half never reaches the panel.
        </li>
        <li className="flex gap-2">
          <span className="font-mono text-faint">2.</span> It opens an SSH reverse tunnel to the panel and
          keeps it supervised.
        </li>
        <li className="flex gap-2">
          <span className="font-mono text-faint">3.</span> The panel sees the tunnel on its allocated port
          and publishes <span className="font-mono text-text">{created.install_script_url.split('/api')[0] || 'the panel'}</span>{' '}
          route for LuCI.
        </li>
      </ol>

      <div className="mt-5 flex items-center justify-between">
        <Button onClick={onBack} icon="chevron-left">
          Back
        </Button>
        <Button variant="primary" iconRight="arrow-right" onClick={onNext} disabled={expired}>
          Watch for connection
        </Button>
      </div>
    </section>
  )
}

/* ------------------------------------------------------------------ rotation */
function StepNeedsRotation({
  routerId,
  rotating,
  onRotate,
  onBack,
  onOpenDetail,
}: {
  routerId: string
  rotating: boolean
  onRotate: () => void
  onBack: () => void
  onOpenDetail: () => void
}) {
  return (
    <section aria-labelledby="rotate-title">
      <h2 id="rotate-title" className="text-sm font-semibold text-text">
        This command is no longer displayed
      </h2>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        The install command was shown exactly once and is not stored anywhere - the server keeps only a
        hash of the bootstrap token. Either the page was reloaded, or you are returning to an older
        wizard. The router record itself is safe.
      </p>

      <div className="mt-4 rounded-lg border border-border bg-surface p-4">
        <div className="flex items-start gap-3">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded border border-warning/30 bg-warning/10 text-warning">
            <Icon name="key" size={15} />
          </span>
          <div className="min-w-0 flex-1">
            <h3 className="text-xs font-medium text-text">Rotate the key to get a new command</h3>
            <p className="mt-1 text-2xs leading-relaxed text-muted">
              This revokes anything the previous command would have installed and mints a fresh
              single-use token. If the router already installed its key, rotating forces it to
              re-register on its next attempt - the tunnel drops until it re-runs the new command.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button variant="primary" icon="refresh" onClick={onRotate} loading={rotating}>
                Rotate and show new command
              </Button>
              <Button onClick={onOpenDetail} icon="external">
                Open router page
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="mt-4 flex items-center justify-between">
        <Button onClick={onBack} icon="chevron-left">
          Back to details
        </Button>
        <span className="font-mono text-3xs text-faint">id {routerId.slice(0, 8)}</span>
      </div>
    </section>
  )
}

/* ------------------------------------------------------------------ step 4 */
const POLL_MS = 2000
const HINTS_AFTER_SECONDS = 60

function StepConnection({
  routerId,
  routerName,
  onBack,
  onDone,
}: {
  routerId: string | null
  routerName: string
  onBack: () => void
  onDone: (id: string) => void
}) {
  const [status, setStatus] = useState<RouterStatus | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const [failures, setFailures] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const doneRef = useRef(false)

  // One interval drives both the poll and the elapsed timer, so they cannot drift.
  useEffect(() => {
    if (!routerId) return
    let cancelled = false

    const tick = async () => {
      try {
        const next = await api.routerStatus(routerId)
        if (cancelled) return
        setStatus(next)
        setFailures(0)
        setError(null)
        if (next.phase === 'done' && !doneRef.current) {
          doneRef.current = true
          // Brief pause so the final step is visible before navigation.
          window.setTimeout(() => onDone(routerId), 900)
        }
      } catch (err) {
        if (cancelled) return
        setFailures((f) => f + 1)
        // A 404 means the router was deleted in another tab - stop hiding that.
        if (err instanceof ApiError && err.status === 404) setError(friendlyMessage(err))
        else if (failures >= 3) setError(friendlyMessage(err))
      }
    }

    void tick()
    const id = window.setInterval(() => {
      setElapsed((e) => e + POLL_MS / 1000)
      void tick()
    }, POLL_MS)

    return () => {
      cancelled = true
      window.clearInterval(id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routerId])

  const phase = status?.phase ?? 'waiting'
  const isOffline = phase === 'offline'
  const activeIndex = PHASES.indexOf(phase as (typeof PHASES)[number])

  const steps = PHASES.map((p, i) => {
    const meta = PHASE_META[p]
    const done = status !== null && i < activeIndex
    const current = status !== null && i === activeIndex
    return {
      label: meta.label,
      detail: current ? meta.detail : done ? 'complete' : undefined,
      state: (done ? 'done' : current ? 'current' : 'todo') as 'done' | 'current' | 'todo' | 'error',
    }
  })

  if (isOffline) {
    steps.push({
      label: 'Tunnel lost',
      detail: 'The router was seen, but its tunnel is no longer up. Check power and uplink.',
      state: 'error',
    })
  }

  const showHints = elapsed >= HINTS_AFTER_SECONDS && phase === 'waiting'

  return (
    <section aria-labelledby="step4-title">
      <h2 id="step4-title" className="text-sm font-semibold text-text">
        Waiting for {routerName}
      </h2>
      <p className="mt-1 text-xs leading-relaxed text-muted">
        This page polls the panel every two seconds. You can leave it open - or close the tab and open
        the router page later; nothing is lost.
      </p>

      <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_260px]">
        <div className="rounded-lg border border-border bg-surface p-4">
          <VerticalStepper steps={steps} />

          <div className="mt-4 flex items-center justify-between border-t border-border pt-3">
            <div className="flex items-center gap-3 text-2xs text-muted">
              <span className="flex items-center gap-1 font-mono tabular-nums">
                <Icon name="clock" size={11} />
                {clockDuration(elapsed)}
              </span>
              {status?.tunnel_present ? (
                <span className="flex items-center gap-1 text-success">
                  <Icon name="wifi" size={11} /> tunnel up
                </span>
              ) : null}
              {status?.health_ok ? (
                <span className="flex items-center gap-1 text-success">
                  <Icon name="check-circle" size={11} /> LuCI healthy
                </span>
              ) : null}
            </div>
            <span className="flex items-center gap-1.5 font-mono text-3xs text-faint" aria-live="polite">
              <Spinner label="Polling" size={9} />
              polling
            </span>
          </div>

          {status?.message ? (
            <p className="mt-2 rounded border border-border bg-surface-2 px-2 py-1.5 font-mono text-3xs text-muted">
              {status.message}
            </p>
          ) : null}

          {error ? (
            <InlineAlert tone="danger" className="mt-3" title="Could not read the status">
              {error}
            </InlineAlert>
          ) : null}
        </div>

        <div className="rounded-lg border border-border bg-surface/60 p-3.5">
          <h3 className="text-2xs font-medium uppercase tracking-wide text-muted">What happens now</h3>
          <ol className="mt-2 space-y-2 text-2xs leading-relaxed text-muted">
            <li>The router exchanges its single-use token for a fresh ed25519 key.</li>
            <li>It opens an SSH reverse tunnel to the panel and keeps it alive.</li>
            <li>The panel sees the listener, checks LuCI health, then marks it online.</li>
            <li>Heartbeats keep hostname, model and firmware version current.</li>
          </ol>
          <div className="mt-3 border-t border-border pt-2 text-3xs leading-relaxed text-faint">
            Nothing about your browser session is involved - you can safely continue in another tab.
          </div>
        </div>
      </div>

      {showHints ? (
        <div className="mt-3 rounded-lg border border-warning/30 bg-warning/[0.05] p-3.5" role="status">
          <h3 className="flex items-center gap-1.5 text-xs font-medium text-warning">
            <Icon name="alert" size={13} />
            Still waiting after a minute
          </h3>
          <p className="mt-1 text-2xs leading-relaxed text-muted">
            Usually one of these four things is wrong. Check them in order.
          </p>
          <dl className="mt-2.5 space-y-2.5">
            {TROUBLESHOOTING.map((t) => (
              <div key={t.title}>
                <dt className="text-2xs font-medium text-text">{t.title}</dt>
                <dd className="mt-0.5 text-3xs leading-relaxed text-muted">{t.body}</dd>
              </div>
            ))}
          </dl>
        </div>
      ) : null}

      <div className="mt-5 flex items-center justify-between">
        <Button onClick={onBack} icon="chevron-left">
          Back to command
        </Button>
        <span className="text-2xs text-faint">id {routerId?.slice(0, 8) ?? '—'}</span>
      </div>
    </section>
  )
}
