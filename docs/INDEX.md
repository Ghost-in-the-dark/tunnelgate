# TunnelGate documentation index

TunnelGate is a FastAPI panel that publishes the LuCI web UI of an OpenWrt router fleet over SSH
reverse tunnels, and adds an interactive browser console into each router. Routers dial out, so no
router needs a public IP, a forwarded port or a VPN client; the panel dials back in over the same
tunnel for its shell. The panel owns the credentials, the nginx routes, the status model and the
audit trail; the router runs a POSIX `sh` agent kept alive by procd. Access is published either as
`https://<slug>.<domain>` (subdomain mode, needs a wildcard certificate) or as
`https://<gateway>/<slug>/` (path mode, needs one ordinary certificate) - see
[docs/ARCHITECTURE.md §5.1](ARCHITECTURE.md) for the trade.

This page is the map. Every document in the repository is listed below, with the question it
answers; if you already know your symptom, jump to [Task to document](#task-to-document).

## Start here

### Operator - install it, then keep it running

1. [docs/INSTALL_SERVER.md](INSTALL_SERVER.md) - decide the DNS/TLS layout, then bring up the VPS:
   base system, firewall, tunnel account, sshd, panel, database, systemd, nginx.
2. [docs/CONFIGURATION.md](CONFIGURATION.md) - every `TUNNELGATE_` setting (`app/config.py`
   defines 63) with its default, what it changes and how it fails when it is wrong.
3. [docs/INSTALL_ROUTER.md](INSTALL_ROUTER.md) - create a router in the panel, run the one-line
   install command, verify the tunnel and the console.
4. [docs/OPERATIONS.md](OPERATIONS.md) - health and status, routine tasks, the common-failure
   table, backup/restore and upgrades, runbooks.
5. [docs/CLI.md](CLI.md) - `python -m app.cli` subcommands (`doctor` first, always).

### Integrator / frontend - call the API, build on the panel

1. [CONTRACT.md](../CONTRACT.md) - the frozen module and wire contract: shared file ownership,
   service module names, testing contract, console addendum.
2. [docs/API.md](API.md) - the HTTP surface, field by field, with the conventions and auth model.
3. [docs/UI.md](UI.md) - the design contract for the SPA: screens, every state they must survive,
   visual system, accessibility.
4. [web/README.md](../web/README.md) - the SPA's file layout, scripts and mock API.

### Contributor - change the code without breaking the contract

1. [CONTRIBUTING.md](../CONTRIBUTING.md) - toolchain, dev loop, pre-commit, exactly what CI runs,
   the doc-guard tests, and the release/version rules.
2. [docs/ARCHITECTURE.md](ARCHITECTURE.md) - planes, onboarding and request sequences, the router
   state machine, data model, failure modes, technology choices.
3. [docs/SECURITY.md](SECURITY.md) - threat model, the two-level token model, the
   `authorized_keys` line and the `restrict` trap, console risks, host hardening.
4. [docs/API.md](API.md) - the routes your change must keep in step with.

## Every document

| Document | Read this when |
|---|---|
| [README.md](../README.md) | you want the pitch, the quick start and the deliberate limits in one page |
| [docs/INSTALL_SERVER.md](INSTALL_SERVER.md) | you are installing, moving or reconfiguring the panel host, or running it behind a proxy/load balancer |
| [docs/CONFIGURATION.md](CONFIGURATION.md) | you need the meaning, default or failure mode of any `TUNNELGATE_` setting |
| [docs/INSTALL_ROUTER.md](INSTALL_ROUTER.md) | you are onboarding, upgrading or removing the agent on a router |
| [docs/OPERATIONS.md](OPERATIONS.md) | something is broken, or you are doing a routine task, a backup, an upgrade or an incident |
| [docs/CLI.md](CLI.md) | you want the exact `app.cli` command, its flags and its output |
| [docs/ARCHITECTURE.md](ARCHITECTURE.md) | you need the design: sequence diagrams, state machine, data model, why the pieces are shaped this way |
| [docs/SECURITY.md](SECURITY.md) | you are reviewing the threat model, keys, the console, auth or host hardening |
| [docs/API.md](API.md) | you are integrating with, or changing, the REST API |
| [docs/UI.md](UI.md) | you are working on the SPA: screens, states, tokens, accessibility |
| [CONTRACT.md](../CONTRACT.md) | you are adding a module or a screen and need the frozen interfaces and file ownership |
| [deploy/README.md](../deploy/README.md) | you are deploying: which artefact goes where, why the reload path is what it is, container vs bare metal |
| [agent/README.md](../agent/README.md) | you are changing the router-side shell code |
| [web/README.md](../web/README.md) | you are working in `web/`: layout, scripts, mock API, contract notes |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | you are about to open a change: dev loop, lint, tests, doc guards, releases |
| [CHANGELOG.md](../CHANGELOG.md) | you want to know what changed in a release, and why |
| [docs/INDEX.md](INDEX.md) | you are new and want the map (this page) |

## Task to document

| Something to do or fix | Go to |
|---|---|
| A router never comes online, or drops to `offline` | [docs/OPERATIONS.md §4](OPERATIONS.md) common-failure table; then [docs/INSTALL_ROUTER.md §7](INSTALL_ROUTER.md) |
| `502`/`403` on a router hostname, or the vhost is missing after adding a router | [docs/OPERATIONS.md §4](OPERATIONS.md); routes are rendered by `app.cli render-proxy` |
| Choose subdomain mode vs path mode, or a wildcard vs one ordinary certificate | [docs/INSTALL_SERVER.md §0](INSTALL_SERVER.md); the trade is in [docs/SECURITY.md §6.1](SECURITY.md) |
| TLS termination, certificates and the nginx site | [docs/INSTALL_SERVER.md §6](INSTALL_SERVER.md); [deploy/README.md](../deploy/README.md) for the artefact inventory |
| The panel is behind a load balancer and audit/rate limits show the proxy's address | [docs/INSTALL_SERVER.md §7](INSTALL_SERVER.md) "Behind a reverse proxy or load balancer"; the app side is `TUNNELGATE_TRUSTED_PROXIES` |
| Which environment variable controls X | [docs/CONFIGURATION.md](CONFIGURATION.md) (complete), [deploy/env/tunnelgate.env.example](../deploy/env/tunnelgate.env.example) (the shipped inventory) |
| Which CLI command does X | [docs/CLI.md](CLI.md) |
| Upgrade the panel; move it to a new host without reinstalling routers | [docs/INSTALL_SERVER.md §9 and §7](INSTALL_SERVER.md); [docs/OPERATIONS.md §5](OPERATIONS.md) |
| Back up or restore the database, keys and routes | [docs/OPERATIONS.md §5](OPERATIONS.md); [docs/INSTALL_SERVER.md §11](INSTALL_SERVER.md) |
| Understand the security model before exposing a router, or review a key line | [docs/SECURITY.md](SECURITY.md) |
| A router rejects the panel's certificate (TLS error, `BADCERT`, "certificate has expired") | [docs/OPERATIONS.md §4](OPERATIONS.md) "A router does not trust the panel's certificate"; the cost of the workaround is in [docs/SECURITY.md §7](SECURITY.md) "When to turn certificate verification off" |
| The console does not open, or you need to kill a live shell | [docs/OPERATIONS.md §4](OPERATIONS.md); [docs/SECURITY.md §5](SECURITY.md) |
| Add or change an API route | [docs/API.md](API.md) - `tests/test_api_docs.py` compares the document and the served routes in both directions |
| Add a module, page or wire shape | [CONTRACT.md](../CONTRACT.md), then [docs/ARCHITECTURE.md](ARCHITECTURE.md), then [docs/UI.md](UI.md) |
| Change the router agent | [agent/README.md](../agent/README.md); CI lints it with `shellcheck -s sh` |
| Run it in Docker instead of on the host | [deploy/README.md](../deploy/README.md); `docker compose up -d --build` |

## Contract and release notes

[CONTRACT.md](../CONTRACT.md) is the frozen frontend/backend contract: read it before you change a
module name, a shared file or a wire shape, because it is what the two halves were built against.
[CHANGELOG.md](../CHANGELOG.md) is the release record - what changed in each version, which release
fixed a symptom, and why the change exists.
