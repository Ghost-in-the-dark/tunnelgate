# TunnelGate panel (web)

The operator-facing SPA for TunnelGate: a single Vite + React + TypeScript
application that lists the router fleet, drives the four-step install wizard,
opens interactive shells and keeps an audit trail. It is served by the same
FastAPI process that serves the API - `app/main.py` mounts `web/dist` at `/`
with a catch-all SPA fallback, so there is no second web server to run in
production.

## Stack

| Piece | Choice | Why |
|---|---|---|
| Build | Vite 6 | one config, fast HMR, real ES module output |
| UI | React 18 + TypeScript (strict) | `strict`, `noUnusedLocals`, `noUncheckedIndexedAccess` are all on |
| Routing | React Router 6 | `BrowserRouter`, lazy routes, `?step=`/`?tab=` as the source of truth |
| Data | TanStack Query 5 | caching, refetch intervals, mutation invalidation |
| Styles | Tailwind 3 + CSS variables | the whole theme is ten `--tg-*` triples |
| Terminal | xterm.js 5 | real terminal emulation with fit + web-links addons |

No component library, no icon package: `src/components/Icon.tsx` is a hand-written
inline SVG set (43 glyphs, stroke 1.75) so nothing extra ships in the bundle.

## Layout

```
web/
  index.html                 # single entry, inline SVG favicon, data-theme="dark"
  package.json               # dev / build / preview / typecheck / mock
  vite.config.ts             # dev proxy for /api + /__tg, manualChunks for xterm
  tailwind.config.js         # colours read rgb(var(--tg-x) / <alpha-value>)
  postcss.config.js
  tsconfig.json              # strict, noEmit, jsx react-jsx
  mock/server.mjs            # throwaway API + static host for previewing the build
  src/
    main.tsx                 # QueryClient + ToastProvider + StrictMode
    App.tsx                  # routes, auth bootstrap, theme boot, lazy pages
    styles/theme.css         # tokens, Tailwind layers, component classes
    lib/
      types.ts               # every wire shape, mirroring app/schemas.py
      api.ts                 # fetch wrapper, in-memory session, CSRF, ApiError
      hooks.ts               # useAuth, useNow, useCountdown, useDebounced, ...
      format.ts              # relativeTime, bytes, pluralize, slugify, uptime
      install.ts             # OS options, wizard steps, command variants, phases
      clipboard.ts           # clipboard with a plain-http fallback
      cn.ts                  # class name joiner
    components/
      AppShell.tsx           # icon rail, top bar, fleet counters, account menu
      HostsTable.tsx         # dense sortable table + column visibility
      AuditTable.tsx         # audit rows with outcome tones
      Field.tsx              # TextField / TextAreaField / SelectField / Toggle
      Button.tsx Modal.tsx Menu.tsx Badge.tsx Kpi.tsx Stepper.tsx
      States.tsx             # Skeleton, EmptyState, ErrorState, InlineAlert, Spinner
      Toast.tsx Icon.tsx
    pages/
      Login.tsx Hosts.tsx NewRouter.tsx RouterDetail.tsx Console.tsx
      Audit.tsx Settings.tsx
```

## Running it

### Against the real API

```sh
cd web
npm ci
npm run build          # tsc --noEmit && vite build  -> web/dist
```

Then start the backend; `app/main.py` serves `web/dist` at `/`. Nothing else is
needed - the SPA calls the API on its own origin and the session cookie is
`HttpOnly`.

### Development with HMR

```sh
cd web
npm run dev            # http://127.0.0.1:5173
```

Vite proxies `/api` (including the WebSocket upgrade) and `/__tg` to
`TUNNELGATE_DEV_BACKEND` (default `http://127.0.0.1:8080`), so the browser still
sees one origin and cookies behave exactly as in production.

### Preview without a backend

`app/api` is not needed to look at the panel. `mock/server.mjs` is a small Node
server that answers the frozen contract with in-memory fixtures and serves
`web/dist` the way `app/main.py` does:

```sh
cd web
npm run build
npm run mock           # http://127.0.0.1:8080   admin / admin
```

It is a development aid only - nothing in the bundle imports it. Sign in as
`admin`, `operator` or `viewer` with password `admin`. Three wrong passwords
lock the account for a few seconds so the 429 countdown can be seen. The mock
also upgrades the console WebSocket, so the terminal is fully interactive
(it echoes keystrokes and runs nothing).

## Screens

| Route | What it does |
|---|---|
| `/login` | sign-in; inline field errors, generic wording on 401, Retry-After countdown on 429, redirect back to the route you wanted |
| `/hosts` | fleet dashboard: four KPI cards that double as filters, dense table with status pills, column visibility, per-row menu, footer pagination |
| `/routers/new` | four-step wizard (OS -> details -> command -> connection) with `?step=` and `?id=` in the URL so a reload resumes |
| `/routers/:id` | overview / install / audit / settings, tab in `?tab=` |
| `/routers/:id/console` | xterm.js shell over the tunnel, with the gate states and the session log |
| `/audit` | every privileged action, filterable by actor and action, CSV export of the current page |
| `/settings` | account, password, appearance; user management (admin); read-only panel config |

Everything is keyboard reachable: `/` focuses search, `Tab` cycles controls,
`Esc` closes dialogs and menus, the mobile/rail links are real `<a>` elements
so middle-click works.

## Theming

`src/styles/theme.css` declares the palette as space-separated RGB triples on
`:root`, and `html.light` overrides every one of them. Tailwind reads them as
`rgb(var(--tg-accent) / <alpha-value>)`, so `bg-accent/10` works and a theme swap
is a single class on `<html>`. The choice is stored in `localStorage` under
`tg-theme` and applied by `useThemeBoot()` before the first paint, so there is
no flash of the wrong theme. `data-theme` is set as well for anything that
prefers attribute selectors.

`prefers-reduced-motion` disables every transition and animation.

## Accessibility

- One `<h1>` per page, landmark regions, a skip link at the top of the shell.
- `aria-current` on the active rail link, `role="tablist"`/`role="tab"` on tabbed views.
- Focus is trapped in modals, restored to the trigger on close, and `Esc` closes.
- `aria-invalid` + `aria-describedby` wire every field error to its input; form
  errors arrive as `details.fields` and land next to the right box.
- Status is never colour alone: pills carry a dot and a word, the freshness bar
  carries its own text.
- Live regions announce async success and failure through `ToastProvider`.

## Performance

100+ routers is the design target, so the list is a plain table with windowed
rendering avoided on purpose (rows are cheap); the expensive work is delegated:

- `manualChunks` puts xterm.js (294 kB) in its own chunk - the host list never
  pays for the terminal.
- Every page except `/hosts` and `/login` is a lazy route.
- Query cache: lists refetch every 5 s, a single router every 8 s, its status
  every 5 s, the console gate every 10 s. Failures are not retried on 4xx.
- Sorting, filtering and pagination are memoised; the search box is debounced
  at 250 ms.

## Contract notes

The wire shapes in `src/lib/types.ts` mirror `app/schemas.py` exactly. Two
consequences worth knowing:

- The install command exists once. `GET /routers/{id}/script` may answer 404
  after the token expired and the UI shows a "rotate and show" empty state
  instead of an error - it is not a failure.
- The audit endpoint has no `outcome` filter, so the outcome dropdown filters
  the current page client-side and says so in an inline note.

## Scripts

| Script | Purpose |
|---|---|
| `npm run dev` | Vite dev server with API proxy |
| `npm run build` | type-check then emit `dist/` |
| `npm run typecheck` | `tsc --noEmit` only |
| `npm run preview` | serve `dist/` without the proxy |
| `npm run mock` | mock API + static `dist/` host on :8080 |

`.shots/` holds local screenshots from the visual pass and is git-ignored.