/** Presentation helpers. Pure functions so they are cheap to test and reuse. */

/** "3m ago", "2h ago" - never a bare timestamp in a dense table. */
export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'never'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return 'unknown'
  const diff = Math.round((now - t) / 1000)
  if (diff < 0) {
    // Clock skew between browser and server: say so instead of "-4s ago".
    return diff > -90 ? 'just now' : `in ${humanDuration(-diff)}`
  }
  if (diff < 10) return 'just now'
  if (diff < 60) return `${diff}s ago`
  return `${humanDuration(diff)} ago`
}

export function humanDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—'
  const s = Math.floor(seconds)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m`.replace(' 0m', '')
  const d = Math.floor(h / 24)
  return `${d}d ${h % 24}h`.replace(' 0h', '')
}

/** Compact timer for the wizard/console: mm:ss or h:mm:ss. */
export function clockDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  const hh = Math.floor(s / 3600)
  const mm = Math.floor((s % 3600) / 60)
  const ss = s % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return hh > 0 ? `${hh}:${pad(mm)}:${pad(ss)}` : `${pad(mm)}:${pad(ss)}`
}

export function absoluteTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function shortFingerprint(fp: string | null | undefined): string {
  if (!fp) return '—'
  // SHA256:xxxxx...yyyyy - keep the type and both ends, which is what operators compare.
  const m = /^(SHA256:[A-Za-z0-9+/=]+)$/.exec(fp.trim())
  if (!m) return fp
  const body = fp.slice(7)
  return body.length <= 18 ? fp : `SHA256:${body.slice(0, 8)}…${body.slice(-8)}`
}

export function bytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

/** Slug preview for the router form; mirrors the server's SLUG_RE rules. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
}

export function uptime(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '—'
  return humanDuration(seconds)
}

/** "eth0"(mac)-style display: group pairs, uppercase, tolerate "aa-bb" input. */
export function formatMac(mac: string | null | undefined): string {
  if (!mac) return '—'
  const clean = mac.replace(/[^0-9a-fA-F]/g, '').toUpperCase()
  if (clean.length !== 12) return mac
  return clean.match(/.{2}/g)!.join(':')
}
