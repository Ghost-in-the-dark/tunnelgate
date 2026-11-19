/** The install-wizard model: options, step machine and the install command variants. */

export interface OsOption {
  id: 'linux' | 'freebsd' | 'windows'
  label: string
  blurb: string
  detail: string
  icon: 'linux' | 'freebsd' | 'windows'
  /** Only Linux has a tuned installer today; the others get the generic POSIX sh path. */
  supported: boolean
}

export const OS_OPTIONS: OsOption[] = [
  {
    id: 'linux',
    label: 'Linux',
    blurb: 'OpenWrt, Debian, Alpine, BusyBox',
    detail:
      'Dropbear or OpenSSH, busybox ash. Uses the router\'s ssh client to keep a reverse tunnel open and reports by heartbeat.',
    icon: 'linux',
    supported: true,
  },
  {
    id: 'freebsd',
    label: 'FreeBSD',
    blurb: 'FreeBSD 13+ with OpenSSH',
    detail: 'The POSIX sh installer runs unchanged; the tunnel is supervised by an rc.d script instead of procd.',
    icon: 'freebsd',
    supported: true,
  },
  {
    id: 'windows',
    label: 'Windows',
    blurb: 'Windows 10/11, Server 2019+',
    detail:
      'Needs the OpenSSH client feature and a POSIX shell (Git Bash or WSL). No native service supervision yet - run it under a scheduled task.',
    icon: 'windows',
    supported: false,
  },
]

export const WIZARD_STEPS = [
  { id: 1, label: 'Choose OS', description: 'Platform' },
  { id: 2, label: 'Router details', description: 'Name and grouping' },
  { id: 3, label: 'Copy command', description: 'No curl needed' },
  { id: 4, label: 'Connection', description: 'Watch it come up' },
]

export interface WizardDraft {
  os_type: 'linux' | 'freebsd' | 'windows'
  name: string
  group_name: string
  integrations: string[]
  notes: string
  http_port: number
}

export const EMPTY_DRAFT: WizardDraft = {
  os_type: 'linux',
  name: '',
  group_name: '',
  integrations: [],
  notes: '',
  http_port: 80,
}

/** Integrations are free-form strings on the wire; these are the ones the UI suggests. */
export const SUGGESTED_INTEGRATIONS = ['singbox', 'openwisp', 'wireguard', 'dhcp-leases', 'firmware-report', 'ddns']

export interface CommandVariant {
  id: 'install' | 'manual'
  label: string
}

/**
 * Two ways to install, and the panel chooses the fetcher in neither of them.
 *
 * The server emits a single command that probes for curl or wget itself, because stock
 * OpenWrt ships neither: /usr/bin/wget there is a symlink to uclient-fetch and the busybox
 * wget applet is absent, and uclient-fetch only gained --header in 24.10. The panel used to
 * rewrite a curl one-liner into a wget one; that rewrite could not work on the routers it
 * targeted, so the command is now shown exactly as served and never edited here.
 */
export const COMMAND_VARIANTS: CommandVariant[] = [
  { id: 'install', label: 'one command' },
  { id: 'manual', label: 'script URL' },
]

/**
 * The command to put in front of the operator.
 *
 * 'install' returns the served string VERBATIM - no substitution, no line dropped, no
 * fetcher swapped. The served text is the only version tested end to end, and a command the
 * panel rewrites is a command nobody tested: that is exactly how the old curl->wget rewrite
 * shipped a one-liner that could not work on a stock OpenWrt. 'manual' returns the bare,
 * token-less script URL for an operator who would rather fetch the installer by hand.
 */
export function commandFor(variant: CommandVariant['id'], installCommand: string, scriptUrl: string): string {
  return variant === 'manual' ? scriptUrl : installCommand
}

export const PHASES = ['waiting', 'connected', 'reporting', 'done'] as const
export type Phase = (typeof PHASES)[number]

export interface PhaseMeta {
  label: string
  detail: string
}

export const PHASE_META: Record<Phase, PhaseMeta> = {
  waiting: {
    label: 'Waiting for connection',
    detail: 'Listening for the router to exchange its bootstrap token. Run the command from step 3.',
  },
  connected: {
    label: 'Connected',
    detail: 'The key was exchanged and the reverse tunnel is up. Waiting for the first heartbeat.',
  },
  reporting: {
    label: 'Receiving initial report',
    detail: 'Heartbeat received. The router is sending its hostname, model and firmware version.',
  },
  done: {
    label: 'Done',
    detail: 'Tunnel healthy and LuCI reachable. Redirecting to the router page…',
  },
}

export const TROUBLESHOOTING: Array<{ title: string; body: string }> = [
  {
    title: 'The router cannot reach this panel',
    body: 'The panel must be reachable over HTTPS on port 443 from the router. Check egress firewall rules, DNS resolution of the panel hostname, and any captive portal.',
  },
  {
    title: 'The token expired or was already used',
    body: 'Bootstrap tokens are single-use and short-lived. Rotate the key to mint a fresh one and re-run the command.',
  },
  {
    title: 'The command ran but nothing happened',
    body: 'Read what the command printed. "Neither curl nor wget is installed on this router" means the image has no fetcher at all; "the panel did not return the installer" means the token was rejected, so mint a fresh command. Then check the clock - a skewed router clock makes the request look expired.',
  },
  {
    title: 'Port forwarding refused',
    body: 'The authorized_keys line needs permitlisten for the tunnel port. If the router has its own sshd config that overrides it, the tunnel cannot bind.',
  },
]
