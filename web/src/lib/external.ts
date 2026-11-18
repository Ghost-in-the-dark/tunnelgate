/**
 * Opening a router's LuCI in a new tab, safely and visibly.
 *
 * `window.open` throws on a URL the browser cannot parse, and it returns null when a popup
 * blocker steps in. Both used to read as "the button does nothing": the click handler threw
 * inside a React event, nothing surfaced, and the operator was left clicking a link that
 * silently failed. The classic way to produce an unparseable URL is a subdomain suffix that is
 * an IP address, which yields https://lab-router.192.168.88.107/ - syntactically odd enough
 * that Chromium rejects it outright (a bare IP may only be the whole host, never a suffix).
 */

export type OpenResult = { ok: true } | { ok: false; reason: string }

/** True when the browser can both parse this URL and would open it. */
export function isOpenableUrl(raw: string | null | undefined): boolean {
  const text = (raw ?? '').trim()
  if (!text) return false
  try {
    const url = new URL(text)
    return url.protocol === 'http:' || url.protocol === 'https:'
  } catch {
    return false
  }
}

/**
 * Why this URL will not open, phrased for an operator rather than a browser console.
 *
 * The IP-suffix case is called out by name because it is the one that looks correct in the
 * panel (the URL renders, it is just unusable) and the fix is a setting, not a click.
 */
export function unopenableReason(raw: string | null | undefined): string {
  const text = (raw ?? '').trim()
  if (!text) return 'There is no public URL for this router yet.'
  try {
    const url = new URL(text)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return `The public URL is not http(s): ${text}`
    }
    return ''
  } catch {
    // <label>.<a.b.c.d>[:port][/...] - a hostname with an IP glued on as the suffix. The trailing
    // path is optional so a bare public URL gets the same explanation as the launch URL.
    const suffixLooksLikeIp = /^[a-z0-9-]+\.\d{1,3}(\.\d{1,3}){3}(:\d+)?(\/|$)/i.test(
      text.replace(/^https?:\/\//, ''),
    )
    if (suffixLooksLikeIp) {
      return (
        'This public URL is not a valid host: its subdomain suffix is an IP address, so the ' +
        'browser cannot open it. Either set TUNNELGATE_SUBDOMAIN_SUFFIX to a real domain (for ' +
        'example router.example.com, which makes lab-router.router.example.com), or drop ' +
        'subdomains entirely with TUNNELGATE_ROUTE_MODE=path and TUNNELGATE_GATEWAY_HOST=gate.example.com, ' +
        'which publishes every router under one host as gate.example.com/lab-router/. Then ' +
        're-render the proxy.'
      )
    }
    return `The public URL is not valid: ${text}`
  }
}

/** Open a URL in a new tab, reporting why it did not happen instead of failing silently. */
export function openExternal(raw: string | null | undefined): OpenResult {
  const text = (raw ?? '').trim()
  const problem = unopenableReason(text)
  if (problem) return { ok: false, reason: problem }
  let win: Window | null = null
  try {
    // Deliberately NOT the 'noopener,noreferrer' feature string: with it window.open returns
    // null by specification, so a blocked popup and a successful open look identical. Dropping
    // the opener afterwards gives the same isolation with a usable return value.
    win = window.open(text, '_blank')
  } catch (err) {
    return { ok: false, reason: `The browser refused to open ${text}: ${String(err)}` }
  }
  if (!win) {
    return { ok: false, reason: 'The browser blocked the new tab. Allow pop-ups for this panel.' }
  }
  try {
    win.opener = null
  } catch {
    /* cross-origin window: the opener is already unusable to the new tab */
  }
  return { ok: true }
}
