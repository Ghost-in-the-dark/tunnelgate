# UI - the TunnelGate panel

This document is the design contract for the panel: what each screen is for, what
states it has to survive, and the conventions everything shares. It is written for
whoever touches `web/` next, and for a reviewer who wants to check the interface
against the product rules rather than against a screenshot.

## 1. What the panel is

An operator tool for a fleet of routers that sit behind SSH reverse tunnels. Every
screen answers one of four questions:

1. **What is the fleet doing right now?** -> `/hosts`
2. **How do I bring a new router in?** -> `/routers/new` (four steps)
3. **What is wrong with this one?** -> `/routers/:id` (overview → install → audit → settings)
4. **Who did what?** -> `/audit`, and `/routers/:id/console` for the shells themselves

The design target is 100+ routers used daily by a small team. Density and
scannability beat decoration; every number on screen is real data with a stated
age, never a placeholder.

## 2. Product rules that shape the UI

These come from the project rules and each one is visible in the interface:

| Rule | How the UI enforces it |
|---|---|
| Private SSH keys never reach the server | the wizard says so in the command panel and again in the overview ("the private half never leaves the router") |
| Bootstrap tokens are single-use, short-lived, SHA-256 only | step 3 is copy-once with a live expiry countdown; the install tab becomes a "rotate and show" empty state once the command is gone (a 404 is a state, not an error) |
| The install command carries only the token | the command block contains the token and nothing secret; the wizard says what it does *not* contain |
| Every privileged action is audited | the detail page has an Audit tab and the console shows the session log; the audit page is a first-class screen, not a debug view |
| Panel needs auth + CSRF | the session lives in an HttpOnly cookie, the CSRF token stays in memory, mutating calls send `X-CSRF-Token`, and the login page states both facts |

## 3. Screen inventory

| Route | Purpose | Primary action |
|---|---|---|
| `/login` | sign in | Sign in |
| `/hosts` | fleet list + health at a glance | Add router |
| `/routers/new?step=N&id=…` | four-step install wizard | Continue → Create and show command → Watch for connection |
| `/routers/:id` with `?tab=` overview, install, audit or settings | one router | Open LuCI / Console / Rotate key |
| `/routers/:id/console` | interactive shell | Connect |
| `/audit` | privileged action log | Export CSV |
| `/settings` with `?tab=` account, users or panel | account, users, read-only config | Update password / Add user |

`/automations` and `/access` exist as rail entries with an honest "coming soon"
placeholder rather than a dead link.

## 4. Shell

A fixed 56px icon rail on the left, a 56px top bar, then the page.

- Rail: five destinations plus the account avatar at the bottom. Each is a real
  `<a>` with `aria-current="page"` when active and a tooltip label on hover;
  middle-click and ctrl-click work like a normal link.
- Top bar: search on the left (with a `/` hint), fleet counters on the right
  (online / offline / pending), page actions last. `/` focuses search from
  anywhere except inside a field.
- Account menu: identity, role, sign out.

## 5. Screen by screen

### 5.1 Login

Centred card, product mark, two fields, one button. It carries the security
story in the footer: access is logged, cookies are HttpOnly, CSRF-protected.

States:

- **idle** - empty form.
- **field errors** - inline under the field, wording that does not leak whether
  the username exists ("Wrong username or password").
- **429** - a warning alert with a live `Retry-After` countdown; the submit
  button is disabled until it reaches zero and re-enables itself.
- **redirect** - signing in from a deep link returns you to the route you asked
  for, not to the dashboard.

### 5.2 Hosts

Four KPI cards, a filter toolbar, a dense table, a footer with page size and
pagination.

**KPI cards double as filters.** Each is a button with `aria-pressed`; the active
one carries an accent border and a "filtered" tag. Total / Needs attention /
Connected / Pending install map to the list envelope's own counters, so the card
and the table can never disagree.

**Table columns:** friendly name + slug, system hostname + reported IP, group,
OS (with firmware under it), agent version, connection pill, integrations, a
freshness bar for the last heartbeat, uptime, last seen, row menu. All but name
and the menu can be hidden from the Columns menu, and the choice survives a
reload. Sorting is click-to-toggle on name, status, last seen and uptime.

**Pills never rely on colour.** Each is a dot plus a word: Online, Offline,
Pending, Awaiting key. Freshness has the same treatment - a bar plus "Live /
Recent / Stale / Never".

**Empty and error states are different things:** no routers at all offers
"Add your first router"; no *matching* routers offers "Clear filters"; a failed
request offers the error message and a Retry button.

### 5.3 Add router wizard

Four steps, and the current step is in the URL (`?step=`) along with the router
id once it exists (`?id=`), so a reload or a shared link resumes where you were.

1. **Choose OS** - three cards (Linux, FreeBSD, Windows) with what each implies
   for supervision; Windows is marked "best effort" rather than hidden.
2. **Router details** - only the name is required. Group is a combobox with
   suggestions from existing groups, integrations are chips with suggestions plus
   free text, notes are free. The slug is derived live from the name.
3. **Copy command** - the token has now been minted, so this step says plainly
   that the command is shown once and cannot be recovered. Three variants (curl,
   wget, manual), a copy button, and a live expiry countdown. When it hits zero
   the field is replaced by a "rotate to mint a new one" state, not by an error.
4. **Connection** - polls the status endpoint, shows a vertical stepper
   (waiting → connected → receiving report → done), an elapsed clock, extra
   hints after a minute, and jumps to the router page on success. The page says
   you can close the tab: nothing is lost.

Reloading step 3 without a token in memory shows a dedicated "needs rotation"
state instead of an empty command box.

### 5.4 Router detail

Header: breadcrumb, name, status pill, integration badges, a mono line with slug,
hostname, client IP and the short id, then the actions - Open LuCI (disabled with
a reason unless the router is online and has a URL), Console (disabled unless the
console is ready), Rotate key, and an overflow menu for copy-URL and delete.

**Overview** - four cards (Tunnel, LuCI health, Uptime, Agent), a facts list, the
public route with copy, an activity timeline, and the connection phase with the
agent's own message. A field the agent has not reported shows an em dash, never a
guess.

**Install** - the single-use warning, the command (or the rotate empty state),
"what the installer does" in four numbered lines, and the three ports assigned to
this router (LuCI on the router, reverse tunnel, console).

**Audit** - the last 50 entries for this router, same table component as `/audit`.

**Settings** - name, group, LuCI port, notes with dirty tracking (Save is only
enabled when something changed, Discard restores), and a danger zone whose delete
flow requires typing the router name. The dialog explains what deletion does and
does not do to the router itself.

### 5.5 Console

An xterm.js terminal in the page, styled from the same CSS variables as the rest
of the UI so it follows the theme.

- **Gate first.** Before a terminal is offered, `GET /routers/{id}/console` is
  checked: `disabled`, `no_key`, `not_installed`, `offline` each get their own
  explanation and their own next step (`no_key` offers "Prepare console").
- **Ticket flow.** Connect calls `console/start` for a short-lived ticket, then
  opens the WebSocket from `ws_path` on the same origin. A failed ticket shows
  the reason in the toolbar, not in the terminal.
- **Toolbar:** state dot, session clock, time left before the hard limit, ticket
  countdown, Disconnect / Reconnect.
- **Session log** below the terminal: user, source address, start, duration,
  bytes in/out, close reason. Admins get a **Kill** action on every row that has
  no close reason yet; it asks first, then closes the session server-side, which
  also stops whatever the user had running in that shell. A kill that the panel
  cannot perform (the session already ended, or no live handler owns it) is
  reported as such instead of leaving a "killed" row pointing at a live shell.

### 5.6 Audit

Actor, action and outcome filters plus the top-bar search bound to the action
filter. The API has no outcome parameter, so the outcome dropdown filters the
current page and an inline note says exactly that - the UI does not pretend.
CSV export writes the rows currently on screen.

### 5.7 Settings

**Account** - identity card with role, change-password form (current, new,
repeat, with a strength meter and match validation), and an appearance picker.
**Users** (admin only) - table with role, status, last sign-in, per-row menu to
edit, disable or delete; your own row cannot disable or delete itself, and the
menu says why.

**Panel** opens with the agent endpoint card: the protocol, host and port a
router dials. Every install command, the installer's heartbeat URL and the URLs
baked into a fetched script use this address, while the proxy keeps using the
internal panel URL - so the two are shown separately and never conflated.

- The card is a form for an admin and a read-only description list for everyone
  else ("Only an admin can change where routers dial").
- A source badge says where the value comes from: "set in panel" once an
  override is stored, "from environment" while `TUNNELGATE_PANEL_URL` is in
  force. Only a stored override offers "Use environment default", behind a
  confirmation that names the URL that will replace it.
- Validation runs on both sides. The client rejects an empty host, a scheme
  instead of a host, spaces/paths/credentials, unusable IPv4 or IPv6 octets and
  an out-of-range port before the request leaves the page; the server stays
  authoritative and its per-field messages land on the matching input. Save
  stays disabled while the form is pristine or invalid, and the live "Routers
  will dial:" preview is suppressed rather than shown for a rejected address.
- "Test connection" probes the panel's own `/api/v1/health` through the
  candidate address and reports inline, in a polite live region (never a toast):
  "Reachable: HTTP 200 in 42 ms" or "Not reachable: <error>", followed by the
  URL that was checked. The button is disabled when the panel has no address it
  could probe from.
- **Ignore SSL self-signed certificates** sits under the port field, phrased as
  an opt-out because the safe default must never read as "the router does not
  check". It is off by default and stays off. Ticking it reveals a warning that
  names what is actually lost - the router can no longer tell the panel from an
  impostor, and the bootstrap token in the install command plus every later API
  token travel over that unverified connection - and it changes two things at
  once: the install command gains `curl -k` / `wget --no-check-certificate`
  behind a leading comment line, and every later heartbeat inherits the same
  `TG_TLS_VERIFY=0`. Over `http` there is no certificate, so the checkbox is
  disabled with "Not applicable: plain HTTP has no certificate to check." and
  the request the form sends still carries `verify_tls: true`; switching back to
  `https` restores whatever the operator had chosen. The choice is part of the
  form's identity, so a change made elsewhere reseeds the checkbox exactly like
  the protocol, host and port - it is never silently kept or silently dropped.
  A viewer sees the resolved state instead: a "Certificate" row reading
  "verified" or "not verified" and, when verification is off, the same warning
  without the control.
- When the panel has no usable endpoint at all (`TUNNELGATE_PANEL_URL` is not a
  valid http(s) URL and nothing is stored) the card explains that no install
  command can point anywhere and, for an admin, still renders the empty form so
  the value can be set here instead of by redeploying.
- Below the card, the remaining rows (internal panel URL, subdomain suffix,
  bootstrap TTL, poll interval, proxy driver, version) stay read-only with the
  reason: these come from `TUNNELGATE_*` variables, because a panel compromise
  must not change how the proxy reaches the panel.

## 6. States every screen must have

| State | Treatment |
|---|---|
| loading | skeleton rows/blocks shaped like the real content, never a spinner in the middle of an empty page |
| empty (no data) | icon, one sentence explaining what this is, one primary action |
| empty (filtered) | icon, "nothing matches", a Clear filters action |
| error | the API's message in plain language, the code for support, a Retry button |
| permission | the control is disabled with a `disabledReason` rather than hidden silently |
| partial data | em dash plus the reason (e.g. "never reported"), never a zero that looks real |
| success | toast in the live region, and the affected query is invalidated |

## 7. Visual system

Tokens live in `web/src/styles/theme.css` as space-separated RGB triples on
`:root`, overridden wholesale by `html.light`. Tailwind reads them as
`rgb(var(--tg-x) / <alpha-value>)`, so alpha modifiers keep working and a theme
switch is one class on `<html>`.

| Token | Role |
|---|---|
| `--tg-bg` `--tg-surface` `--tg-surface-2/3` | page, card, raised, hover |
| `--tg-border` `--tg-border-strong` | hairlines, hover borders |
| `--tg-text` `--tg-muted` `--tg-faint` | primary, secondary, tertiary text |
| `--tg-accent` `--tg-accent-2` | interactive accent, gradient partner |
| `--tg-success` `--tg-warning` `--tg-danger` | state colours, always paired with a word |

Type: 13px UI base, 11-12px for dense table cells and metadata, 10-11px for
uppercase labels with letter-spacing. Numbers in tables are tabular.

Radii are 6/10/14/18px; cards use 14. Shadows are two soft layers, never a hard
drop shadow. Motion is 120-180ms and disabled entirely under
`prefers-reduced-motion`.

## 8. Accessibility

- Every page has one `<h1>` and they descend in order.
- The shell has a skip link; rails and tabs are landmarks/NavLists, not div soup.
- Focus is visible everywhere (`:focus-visible` outline), trapped inside modals,
  and restored to the trigger when a modal closes.
- Menus respond to ArrowUp/ArrowDown/Home/End/Escape and close on outside click.
- Field errors are wired with `aria-invalid` and `aria-describedby`; the server's
  `details.fields` land next to the matching input.
- Async outcomes are announced through a polite live region.
- Status is never conveyed by colour alone.

## 9. Performance rules

- The router list is a plain table; 100+ rows stay responsive because sorting and
  filtering are memoised and the search box is debounced.
- xterm.js is isolated in its own chunk, so the fleet dashboard never downloads
  the terminal.
- All pages except the list and login load lazily.
- Poll intervals are deliberate: fleet 5s, router 8s, status 5s, console gate 10s,
  audit 15s. 4xx responses are not retried.

## 10. What is mocked today

`web/mock/server.mjs` implements the frozen contract in memory so the panel can be
demoed before the API lands: six routers across all four states, four users with
all three roles (one disabled), 84 audit rows, two console sessions, and a
WebSocket console that echoes keystrokes. Two deliberate rough edges are
reproduced so the UI's handling of them can be seen: `GET /{id}/script` answers
404 (command not kept) and a fourth bad password answers 429 (rate limited).

Run it with `npm run mock` after `npm run build`; sign in as `admin` / `admin`.