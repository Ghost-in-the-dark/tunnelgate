# Contributing to TunnelGate

This file is the development workflow and the contract you have to satisfy before a change can
land. It documents what CI already enforces - if a command is listed here, it runs on every pull
request and the build fails when it does not pass.

If you only read one other document, read [CONTRACT.md](CONTRACT.md) before you add a module, a
route or a wire shape: the frontend and the backend were built against it, and it is not advisory.

## Toolchain

| Piece | Version | Where it comes from |
|---|---|---|
| Python | 3.11+ to run, **3.13** in CI | `pyproject.toml` `requires-python = ">=3.11"`; CI pins `PYTHON_VERSION: "3.13"` |
| Node | **22** in CI | `NODE_VERSION: "22"` in `.github/workflows/ci.yml` |
| Ruff | >= 0.8 (`requirements-dev.txt`), 0.17.5 in pre-commit | `requirements-dev.txt`, `.pre-commit-config.yaml` |
| Shellcheck | pin `shellcheck-py>=0.10` locally | `requirements-dev.txt` |

A newer local Node is usually fine, but `npm test` runs `node --test "src/**/*.test.ts"` against
TypeScript directly: Node strips types natively only from 23.6/24 onward unflagged, so a Node 22
pin is what CI proves. Check your local versions against the CI pins before blaming the build.

## Set up

```bash
git clone https://github.com/Ghost-in-the-dark/tunnelgate.git && cd tunnelgate
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
(cd web && npm ci && npm run build)
```

The frontend build is not optional for running the app: `app/main.py` mounts `web/dist` at `/`,
so a fresh clone with no build serves an empty shell. Rebuild after any change under `web/src`.

## Run it

```bash
./scripts/dev.sh            # :8080 by default
./scripts/dev.sh 9000       # any port
```

`scripts/dev.sh` exports `TUNNELGATE_DATA_DIR` (default `./data`) and
`TUNNELGATE_ADMIN_PASSWORD` (default `admin-changeme-now`), then runs
`uvicorn app.main:app --host 127.0.0.1 --port <port> --reload`. Both variables are overridable
from the environment, so `TUNNELGATE_ADMIN_PASSWORD=... ./scripts/dev.sh` wins. The development
default `proxy_driver` is `none`, so routers are reachable at `http://127.0.0.1:<tunnel_port>`
without nginx.

### The web side, split out

The SPA has its own loop and its own mock backend:

| Command (from `web/`) | What it does |
|---|---|
| `npm run dev` | Vite dev server on `http://127.0.0.1:5173`, proxying `/api` (with the WebSocket upgrade) and `/__tg` to `TUNNELGATE_DEV_BACKEND` (default `http://127.0.0.1:8080`) |
| `npm run build` | `tsc --noEmit && vite build` into `web/dist` |
| `npm run preview` | serve `web/dist` without the proxy |
| `npm run typecheck` | `tsc --noEmit` only |
| `npm test` | `node --test "src/**/*.test.ts"` |
| `npm run mock` | `node mock/server.mjs`: mock API plus static host for `web/dist` on `http://127.0.0.1:8080`, log in `admin` / `admin` |

`npm run mock` serves the **built** `dist`, not `src`, so run `npm run build` first or you will
look at a stale bundle. The mock is a development aid only; nothing in the production bundle
imports it.

## Pre-commit

```bash
.venv/bin/pip install pre-commit
pre-commit install
```

`.pre-commit-config.yaml` installs both `pre-commit` and `commit-msg` hook types. The hooks:

| Hook | Scope |
|---|---|
| `trailing-whitespace`, `end-of-file-fixer`, `mixed-line-ending --fix=lf` | every file |
| `check-yaml`, `check-json` | config files; `web/package-lock.json` and `web/tsconfig*.json` are excluded |
| `check-added-large-files --maxkb=512` | refuses a large blob |
| `check-merge-conflict`, `check-executables-have-shebangs` | every file |
| `ruff --fix`, `ruff-format` | `app/` and `tests/` `*.py` |
| `shellcheck -s sh -e SC1091,SC3043,SC2039` | `agent/*.sh` |
| `shellcheck -s bash -e SC1091` | `scripts/*.sh`, `deploy/*.sh` |
| `prettier --single-quote --print-width 100` | `web/src/**/*.{ts,tsx,css}` |
| `python-import-smoke` (local) | `python -c "import sys; sys.path.insert(0, '.'); from app.main import app"` whenever `app/**/*.py` changes |
| `no-private-keys` (local) | refuses any commit containing `BEGIN (OPENSSH\|RSA\|EC\|DSA) PRIVATE KEY` |

The private-key hook is not decorative: TunnelGate's whole design assumes the panel never stores a
router's private key, so key material in the tree is treated as a defect.

## What CI runs

Four jobs, all on every push to `main`, every tag `v*` and every pull request.

**backend (lint + tests)** - Python 3.13:

```bash
ruff check app tests
ruff format --check app tests
python -c "from app.main import app; print(app.title)"
TUNNELGATE_ENV=test TUNNELGATE_SECRET_KEY=ci-test-secret-key pytest -q --tb=short
```

The `ruff check` line tries `app tests agent_runner` first and falls back to `app tests`; on this
tree only `app tests` exists. Run the suite yourself with `.venv/bin/python -m pytest -q` - it is
fast because each test gets a temp database.

**frontend (typecheck + build)** - Node 22, working directory `web`:
`npm ci`, `npm run typecheck`, `npm test`, `npm run build`, then `test -f dist/index.html` so a
build that emits nothing cannot pass.

**router installer (shellcheck + dry run)**:
`shellcheck -s sh -e SC1091,SC3043,SC2039 agent/install.sh agent/uninstall.sh agent/tunnelgate.init agent/lib/*.sh`,
the same rules over `scripts/quick-install.sh` and `scripts/update.sh`, `busybox sh -n` on
`agent/install.sh agent/uninstall.sh agent/tunnelgate.init scripts/quick-install.sh scripts/update.sh`,
then `pytest -q tests/test_installer.py`.

**deploy artefacts parse**:
`docker compose -f docker-compose.yml config` after materialising `/etc/tunnelgate.env` from
`deploy/env/tunnelgate.env.example`; `nginx -t` for `deploy/nginx/tunnelgate.conf` inside
`nginx:1.27-alpine` with a stub certificate and route include; `systemd-analyze verify` on
`deploy/systemd/*.service`.

Reproduce the checks you touched before pushing rather than waiting for CI:

```bash
ruff check app tests
ruff format --check app tests
.venv/bin/python -m pytest -q
(cd web && npm run typecheck && npm test && npm run build)
shellcheck -s sh -e SC1091,SC3043,SC2039 agent/*.sh scripts/quick-install.sh scripts/update.sh
```

Some tests are end-to-end and need a local sshd; they carry `@pytest.mark.e2e` (in
`tests/test_installer.py`) and skip themselves when it is absent.

## Two tests that will fail on a docs change

These are the guard rails you will actually trip over. Both fail loudly and both are right to.

**`tests/test_version.py`** - one version, four files, and every documented pin:

* `app/__init__.py` `__version__`, `pyproject.toml` `[project].version`,
  `web/package.json` `version` and `web/package-lock.json` (`version` and
  `packages[""].version`) must be the same string.
* `CHANGELOG.md` must open with `## [<current version>] - YYYY-MM-DD`, sections must be in
  descending order with no duplicates, and there must be no `## [Unreleased]` placeholder.
* every `--ref vX.Y.Z`, every `/vX.Y.Z/scripts/` URL and every `checkout vX.Y.Z` in `README.md`
  and `docs/*.md` must name the version in the tree.
* every script the docs pipe (`scripts/quick-install.sh`, `scripts/update.sh`) must exist.
* `agent/install.sh` keeps its own `CLIENT_VERSION`, deliberately not the panel's semver: a panel
  patch release must not force a router reinstall.

So: **if you bump the version, bump all four strings and open a changelog section in the same
commit.** If you add a command to a document with a tag in it, the tag has to be one the tree
carries.

**`tests/test_api_docs.py`** - `docs/API.md` and the routes the app serves are compared in both
directions: a served route missing from the document fails, and a documented route with no handler
fails too. WebSocket routes come from the API routers, HTTP routes from the OpenAPI schema.
So: **if you add, rename or delete a route, update `docs/API.md` in the same commit.**

## Release and commit conventions

The changelog format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). `CHANGELOG.md` explains this at
the top; read the newest release before writing the next one, because the entries explain *why* a
change exists, not only what changed.

A release is one commit that:

1. bumps `app/__init__.py`, `pyproject.toml`, `web/package.json` and `web/package-lock.json` to
   the same version,
2. adds a `## [x.y.z] - YYYY-MM-DD` section at the top of `CHANGELOG.md` (no `[Unreleased]`),
3. updates any version pinned in `README.md` or `docs/*.md`,
4. is tagged `vx.y.z` - CI builds tags, so the run a release links to is the one that tested the
   bytes it ships.

Router and panel versions are separate by design; do not tie `CLIENT_VERSION` to the panel
version.

## Where things live

`app/` is the FastAPI application (`api/` routers, `services/` domain logic, plus `config.py`,
`db.py`, `models.py`, `schemas.py`, `security.py`, `deps.py`, `errors.py`, `main.py`, `cli.py`).
`agent/` is the POSIX `sh` router agent. `deploy/` holds reference host artefacts the panel never
imports. `web/` is the React + TypeScript + Vite SPA. `tests/` is the pytest suite and `docs/` the
documents. The full map with a route for each audience is
[docs/INDEX.md](docs/INDEX.md); the file-by-file inventory is in
[README.md](README.md#repository-layout).

Read [CONTRACT.md](CONTRACT.md) before touching a shared file: it names the modules each owner
creates, the decisions that are settled, and the write scopes. If a change crosses those lines,
raise it rather than rewriting the contract.
