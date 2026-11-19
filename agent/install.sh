#!/bin/sh
# TunnelGate router agent installer (OpenWrt, POSIX sh / busybox ash).
#
# This script is served BY THE PANEL and is the only thing an operator runs on the router:
#
#   TK='<token>'; U='https://panel.example.com/api/v1/routers/install?os=linux'; F=/tmp/tg-install.$$.sh
#   if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$F" -u "$TK:" "$U"
#   elif command -v wget >/dev/null 2>&1; then wget -q -O "$F" --user="$TK" --password=x "$U"
#   else echo 'TunnelGate: neither curl nor wget is installed on this router' >&2; exit 1; fi
#   grep -q 'TunnelGate router agent installer' "$F" || { rm -f "$F"; exit 1; }
#   sh "$F"
#
# Fetch to a file and check it before running it: piping straight into sh would turn the empty
# body of a 401 into a silent success. The token rides as the basic-auth USERNAME, which is the
# only credential channel both fetchers honour (stock /usr/bin/wget is uclient-fetch: no
# --header before 24.10, and no retry of a challenged POST, so --password alone cannot carry
# it). The placeholder password exists to keep the colon in base64(TOKEN:x) - uclient-fetch drops
# it when the password is empty or absent. The token does land in the router shell history; it
# is single-use and short-lived.
#
# The server substitutes two placeholder lines before serving it. They must appear exactly
# once each, alone on their line, and are the ONLY channel through which the panel URL and
# the single-use bootstrap token reach the router (a token in a URL would land in the router's
# shell history, in wget's argv and in the proxy access log):
#
#@@PANEL_URL_LINE@@
#@@BOOTSTRAP_TOKEN_LINE@@
#
# The exchange response carries the router's new ed25519 PRIVATE key exactly once. It is
# written straight to a 0600 file and never echoed, logged or passed on a command line.
#
# TLS: the panel injects TG_TLS_VERIFY together with the URL and the token (1 = verify,
# 0 = accept a certificate that does not chain to a trusted CA, i.e. a self-signed panel
# certificate). It is the ONLY source of -k / --no-check-certificate in this script: nothing
# here disables certificate checking globally, and a value that is not exactly "0" verifies.
#
# Why the agent does not use autossh: another package on top of a firmware upgrade, and no
# control over the reconnect policy. procd already supervises processes, so a plain loop with
# a fixed back-off covers "reconnect forever" and keeps the failures in logread.

set -u
# Every file this script creates starts out private. The private temporary directory is already
# 0700, but a mode inside it must not depend on that alone: a body file that carries the bootstrap
# token, or a response that carries the private key, is worthless to an attacker only while it is
# unreadable in its own right. Everything that must be executable or readable is chmod'ed
# explicitly below, so this default never gets in the way.
umask 077

CLIENT_VERSION="1.0"
EXCHANGE_PATH="/api/v1/routers/bootstrap/exchange"

# Absolute paths on a real OpenWrt install. Each can be redirected for testing (the test
# suite points them into a temp directory so a test run never writes to /etc or /root).
STATE_DIR="${TG_STATE_DIR:-/usr/lib/tunnelgate}"
JSON_LIB="$STATE_DIR/json.sh"
KEY_PATH="${TG_KEY_PATH:-/root/.ssh/tunnelgate_ed25519}"
KNOWN_HOSTS="${TG_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
CONFIG="${TG_CONFIG:-/etc/config/tunnelgate}"
INITD="${TG_INITD:-/etc/init.d/tunnelgate}"
LOOP_BIN="${TG_LOOP_BIN:-/usr/bin/ssh-loop}"
HB_BIN="${TG_HB_BIN:-/usr/bin/tunnelgate-heartbeat}"
UNINSTALL_BIN="${TG_UNINSTALL_BIN:-/usr/bin/tunnelgate-uninstall}"
# The account database the console-user step reads a home directory from. Same reason as the
# other overrides: a test has to be able to describe a console account without creating one.
PASSWD_FILE="${TG_PASSWD:-/etc/passwd}"
# The release file the version checks read. Same reason as the other overrides: a test run has to
# be able to say "pretend this is 19.07" without editing /etc.
OPENWRT_RELEASE_FILE="${TG_OPENWRT_RELEASE:-/etc/openwrt_release}"
# Where a TLS-capable libustream would be. Same reason as the other overrides: a test has to
# be able to say "this image does ship one" without writing into /lib.
TLS_LIB_DIRS="${TG_TLS_LIB_DIRS:-/lib /usr/lib}"
# Exactly the set the installer adds (and agent/uninstall.sh removes): the client on its own does
# not provide ssh-keygen or ssh-keyscan - they live in the other two packages.
OPENSSH_PKGS="openssh-client openssh-keygen openssh-client-utils"
# TG_SKIP_SERVICE=1 stages the files but does not call the init script (test suite only).
SKIP_SERVICE="${TG_SKIP_SERVICE:-0}"
# Private working directory for the exchange. Created lazily and only when something is
# actually written, with umask 077, so a file that carries a bootstrap token, an API token or
# a private key is never world-readable and never at a path another local user could have
# pre-created as a symlink (a bare "/tmp/name.$$" is guessable; choosing it before the open is
# the classic bug). $$ is the pid, so two installers cannot collide; mktemp -d also refuses a
# directory that already exists.
TMP_DIR=""
DEF_RESPONSE=""   # set once the directory exists
DEF_BODY=""
HTTP_ERR_FILE=""

# 1 when this router's fetcher probably cannot check a certificate chain (see
# tls_stack_cannot_verify). Decided ONCE in main, after the TLS library work.
TLS_UNVERIFIABLE=0

MODE="install"
DRY_RUN=0
PURGE=0
RESPONSE_FILE=""
BODY_FILE=""

# make_tmp_dir: create the private directory and point the three paths at it. Called right
# before the first write, never at startup - a --dry-run that never touches the network should
# leave nothing behind at all.
make_tmp_dir() {
    [ -n "$TMP_DIR" ] && return 0
    # umask 077 covers the window between mktemp choosing the name and the file being created;
    # mktemp -d itself creates 0700 and refuses a path that already exists.
    TMP_DIR=$(umask 077; mktemp -d "${TMPDIR:-/tmp}/tunnelgate.$$.XXXXXX" 2>/dev/null) || {
        err "cannot create a private temporary directory under ${TMPDIR:-/tmp}"
    }
    chmod 0700 "$TMP_DIR" 2>/dev/null
    DEF_RESPONSE="$TMP_DIR/exchange.json"
    DEF_BODY="$TMP_DIR/report.json"
    HTTP_ERR_FILE="$TMP_DIR/fetch.err"
    RESPONSE_FILE="$DEF_RESPONSE"
    BODY_FILE="$DEF_BODY"
}

# The HTTP fetcher, probed ONCE (http_post explains why the two are not interchangeable).
# Values: curl | wget | none. Stock OpenWrt has no curl at all and its wget is uclient-fetch;
# "none" is a stripped image that cannot reach the panel on its own.
FETCHER=""
detect_fetcher() {
    if command -v curl >/dev/null 2>&1; then
        FETCHER=curl
    elif command -v wget >/dev/null 2>&1; then
        FETCHER=wget
    else
        FETCHER=none
    fi
}

# TLS policy for the panel connection.
#
# The panel injects TG_TLS_VERIFY as a shell assignment (1 = verify, 0 = the panel's certificate
# cannot be validated against the system CA store). A saved script re-run by hand has the value
# baked in; when it is absent, the UCI option this installer wrote is used instead, so
# 'uci set tunnelgate.main.tls_verify=0' survives a re-install.
#
# ONLY the exact string "0" turns verification off. "1", "yes", "2", "false", "" and anything
# else mean VERIFY: a value we do not understand must never silently downgrade the connection
# that carries the bootstrap token and, afterwards, the API token.
TLS_VERIFY=1

# The raw option from the config file (empty when it is not there yet).
config_tls_verify() {
    sed -n "s/^[[:space:]]*option[[:space:]]*tls_verify[[:space:]]*'\(.*\)'[[:space:]]*$/\1/p" \
        "$CONFIG" 2>/dev/null | head -n 1
}

resolve_tls_verify() {
    _v=${TG_TLS_VERIFY:-}
    if [ -z "$_v" ]; then
        _v=$(config_tls_verify)
    fi
    if [ "$_v" = "0" ]; then
        TLS_VERIFY=0
    else
        TLS_VERIFY=1
    fi
}

log() {
    logger -t tunnelgate "$*" 2>/dev/null
    printf '[tunnelgate] %s\n' "$*"
}

err() {
    log "error: $*"
    exit 1
}

usage() {
    cat <<'USAGE'
TunnelGate router installer.

  This script is normally served by the panel; it is not meant to be downloaded by hand.

  Usage: sh install.sh [--status] [--restart] [--uninstall [--purge]] [--dry-run]

    --status      print service state and the installed UCI configuration
    --restart     restart both procd instances
    --uninstall   stop and remove the agent (keeps the panel-side router record)
    --purge       with --uninstall: also remove openssh-client, openssh-keygen and
                  openssh-client-utils (the packages this script may have installed)
    --dry-run     print what would happen; touches neither the filesystem nor the API

  Requires root. TG_FORCE=1 skips the OpenWrt check (development/testing only).

  The two placeholder lines near the top are substituted by the server. If you saved this
  script and re-run it later that is fine: the substitution is already baked in.
USAGE
}

cleanup() {
    [ -n "$DEF_RESPONSE" ] && rm -f "$DEF_RESPONSE"
    [ -n "$DEF_BODY" ] && rm -f "$DEF_BODY"
    [ -n "$HTTP_ERR_FILE" ] && rm -f "$HTTP_ERR_FILE"
    rm -rf "${TMPDIR:-/tmp}/tg-probe.$$" 2>/dev/null
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    TMP_DIR=""
}

# on_signal: a trapped signal must still end the process. A handler that only cleans up
# returns to the interrupted code, so Ctrl-C during the exchange carried on with the install
# - the cleanup ran, the script did not stop.
on_signal() {
    cleanup
    trap - EXIT INT TERM
    exit 130
}

trap cleanup EXIT
trap on_signal INT TERM

# --------------------------------------------------------------------------------------
# arguments
# --------------------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
        --status) MODE="status" ;;
        --restart) MODE="restart" ;;
        --uninstall) MODE="uninstall" ;;
        --purge) PURGE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --help | -h)
            usage
            exit 0
            ;;
        *) err "unknown argument: $1 (try --help)" ;;
        esac
        shift
    done
    if [ "$PURGE" = "1" ] && [ "$MODE" != "uninstall" ]; then
        err "--purge is only valid together with --uninstall"
    fi
}

# --------------------------------------------------------------------------------------
# sanity
# --------------------------------------------------------------------------------------
check_root() {
    [ "$(id -u)" = "0" ] ||
        err "must run as root (the installer writes /etc/config, /etc/init.d and /root/.ssh)"
}

check_openwrt() {
    if [ "${TG_FORCE:-0}" = "1" ]; then
        log "TG_FORCE=1: skipping the OpenWrt check (development mode)"
        return 0
    fi
    [ -r "$OPENWRT_RELEASE_FILE" ] ||
        err "this does not look like OpenWrt ($OPENWRT_RELEASE_FILE is missing); set TG_FORCE=1 only for testing"
}

# A body that is not this script (a 401 page, a captive-portal splash, an HTML error page) must
# never be half-executed. The panel's install command fetches to a file and greps for the
# sentinel before running it; this is the same guard from inside the file. Piped into a shell
# there is nothing to read back and $0 names the shell itself, so that case is skipped.
#
# The sentinel is NOT on line 2 of a served script: app/services/bootstrap.py::render_install_script
# prepends a header of TG_* assignments (six lines today, and it may grow), which pushes this
# file's own header down. Scanning a fixed two lines therefore rejected every real install -
# the panel-side grep searched the whole body and passed, and then the script refused itself.
# Scan a generous window of the TOP of the file instead: it stays cheap on a router, it does not
# care how many lines the panel injects, and a line far down a captive-portal page cannot vouch
# for the file (the whole point is that the installer starts with its own header).
SELF_SCAN_LINES=40
check_self() {
    case "$0" in
    "" | sh | -sh | dash | ash | bash | busybox) return 0 ;;
    esac
    [ -r "$0" ] || return 0
    head -n "$SELF_SCAN_LINES" "$0" 2>/dev/null | grep -q 'TunnelGate router agent installer' && return 0
    err "$0 does not look like the TunnelGate installer (its header line is missing): the panel did not return the script, so mint a fresh install command and retry"
}

# The two placeholder lines are substituted by the server. When they are still verbatim
# placeholders the script was downloaded raw (or the panel's renderer is broken) - there is
# no token and no URL, so fail with an explanation instead of building a request to "".
check_placeholders() {
    # shellcheck disable=SC2154  # _val is assigned by eval on the next line
    for _name in TG_PANEL_URL TG_BOOTSTRAP_TOKEN; do
        # Indirect expansion: build "_val=${TG_PANEL_URL:-}" and let eval expand it.
        # ("_val=${_name:-}" would assign the NAME, not the value - a silent no-op.)
        eval "_val=\${$_name:-}"
        case "$_val" in
        "")
            err "${_name} is not set: this script must be served by the panel (the server substitutes the placeholder lines). Do not download it by hand"
            ;;
        "#@@"*)
            err "${_name} still contains a placeholder line: the panel did not substitute it. Re-generate the install command in the panel"
            ;;
        esac
    done
    # set -u is on: expand with a default so an unset variable reaches the message above
    # instead of dying inside the shell with "parameter not set".
    case "${TG_PANEL_URL:-}" in
    http://* | https://*) ;;
    *) err "TG_PANEL_URL must start with http:// or https:// (got '${TG_PANEL_URL:-}')" ;;
    esac
    # ${#name} takes no default; the loop above has already exited when the token is
    # unset, so a plain length expansion is safe here under set -u.
    _token_len=${#TG_BOOTSTRAP_TOKEN}
    [ "$_token_len" -ge 16 ] ||
        err "TG_BOOTSTRAP_TOKEN looks truncated ($_token_len chars); re-generate the install command"
}

# --------------------------------------------------------------------------------------
# platform / packages
# --------------------------------------------------------------------------------------
detect_pkg_manager() {
    if command -v apk >/dev/null 2>&1; then
        echo apk
    elif command -v opkg >/dev/null 2>&1; then
        echo opkg
    else
        echo none
    fi
}

run_cmd() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: $*"
        return 0
    fi
    "$@"
}

# dropbear cannot enforce per-key permitlisten restrictions and its -R handling is
# unreliable, so the agent runs OpenSSH's client. (The console channel goes the other way:
# the panel connects INTO dropbear, which needs nothing from us beyond a public key.)
# dropbear cannot enforce per-key permitlisten restrictions and its -R handling is
# unreliable, so the agent runs OpenSSH's client. (The console channel goes the other way:
# the panel connects INTO dropbear, which needs nothing from us beyond a public key.)
#
# DETECTING it is the hard part, because a stock OpenWrt lies about it - measured on
# openwrt/rootfs:x86-64 19.07.10 / 22.03.7 / 23.05.5 / 24.10.1 / SNAPSHOT:
#
#   /usr/bin/ssh        -> /usr/sbin/dropbear   on ALL of them
#   /usr/bin/ssh-keygen -> /usr/sbin/dropbear   on 24.10 and SNAPSHOT (absent on the older ones)
#   /usr/bin/ssh-keyscan                        absent on all of them
#
# so "command -v ssh" succeeds everywhere and proves nothing, and even "command -v ssh-keygen"
# is satisfied by dropbear on 24.10. Worse, dropbear's ssh-keygen impersonation cannot read an
# OpenSSH private key - it prints "Exited: String too long" AND EXITS 0, so an exit-code check
# reports success on a key that nothing can use.
#
# Hence one probe per capability the agent actually needs, and the keygen one is FUNCTIONAL:
# real OpenSSH prints "ssh-ed25519 ..." for the known key below, dropbear prints nothing.
#
# ALSO: "opkg install openssh-client" is NOT enough. Measured file lists on 23.05.5:
#   openssh-client       -> /usr/libexec/ssh-openssh, /etc/ssh/ssh_config  (no keygen, no keyscan)
#   openssh-keygen       -> /usr/libexec/ssh-keygen-openssh               (repoints /usr/bin/ssh-keygen)
#   openssh-client-utils -> /usr/bin/ssh-keyscan, ssh-agent, ssh-keysign, ssh-add
# apk (24.10-era SNAPSHOT and later, apk-tools 3.0.5) carries the same three packages with the
# same split. With only openssh-client installed, the install dies later at pin_host_key
# ("ssh-keyscan is missing") and at install_private_key ("not usable by ssh-keygen").

# probe_openssh <capability>: 0 when the capability really works. No output, no leftovers.
# ssh-keygen is probed by GENERATING a key, never by testing a fixture we ship: this script is
# served to every router, so it must not carry key material (a test enforces that), and
# generation is a stronger test anyway. On every stock image /usr/bin/ssh-keygen is a symlink to
# dropbear, which cannot write an OpenSSH-format key; OpenSSH's own can. Reading the result back
# with -y proves the read path install_private_key() depends on, and grepping the header pins the
# FORMAT so a non-OpenSSH keygen that happens to emit PKCS#8 still fails.
probe_openssh() {
    case "$1" in
    ssh)
        ssh -V 2>&1 | grep -q 'OpenSSH_'
        return $?
        ;;
    ssh-keygen)
        _probe_dir="${TMPDIR:-/tmp}/tg-probe.$$"
        _probe_ok=1
        if mkdir -p "$_probe_dir" 2>/dev/null &&
            (umask 077; ssh-keygen -q -t ed25519 -N '' -f "$_probe_dir/probe") >/dev/null 2>&1 &&
            head -n 1 "$_probe_dir/probe" 2>/dev/null | grep -q 'OPENSSH PRIVATE KEY' &&
            ssh-keygen -y -f "$_probe_dir/probe" 2>/dev/null | grep -q '^ssh-ed25519 '; then
            _probe_ok=0
        fi
        rm -rf "$_probe_dir" 2>/dev/null
        return "$_probe_ok"
        ;;
    ssh-keyscan)
        command -v ssh-keyscan >/dev/null 2>&1
        return $?
        ;;
    esac
    return 1
}

# The capabilities that do not hold, each already naming the package that supplies it.
# Empty output means the OpenSSH client is fully usable.
openssh_gaps() {
    _gaps=""
    probe_openssh ssh ||
        _gaps="ssh is not OpenSSH (it is dropbear) - needs openssh-client"
    probe_openssh ssh-keygen ||
        _gaps="${_gaps:+${_gaps}; }ssh-keygen cannot read an OpenSSH private key - needs openssh-keygen"
    probe_openssh ssh-keyscan ||
        _gaps="${_gaps:+${_gaps}; }ssh-keyscan is missing - needs openssh-client-utils"
    printf '%s' "$_gaps"
}

ensure_openssh() {
    _gaps=$(openssh_gaps)
    if [ -z "$_gaps" ]; then
        log "OpenSSH client present (ssh, ssh-keygen and ssh-keyscan all work)"
        return 0
    fi
    _pkg=$(detect_pkg_manager)
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: OpenSSH is not usable ($_gaps); would install openssh-client openssh-keygen openssh-client-utils via $_pkg"
        return 0
    fi
    log "OpenSSH is not usable: $_gaps"
    case "$_pkg" in
    apk)
        log "installing openssh-client openssh-keygen openssh-client-utils via apk"
        run_cmd apk add --no-cache openssh-client openssh-keygen openssh-client-utils ||
            log "warning: apk reported a failure; re-probing before giving up"
        ;;
    opkg)
        # /var/lock and /var/run are tmpfs on a booted router; a bare container (or an image
        # being repaired over a serial console) has neither, and opkg then dies before
        # downloading anything: "opkg_conf_load: Could not create lock file /var/lock/opkg.lock".
        mkdir -p /var/lock /var/run 2>/dev/null || true
        log "installing openssh-client openssh-keygen openssh-client-utils via opkg"
        run_cmd opkg update || log "warning: opkg update failed, trying the install anyway"
        run_cmd opkg install openssh-client openssh-keygen openssh-client-utils ||
            log "warning: opkg reported a failure; re-probing before giving up"
        ;;
    *)
        err "no apk or opkg found; cannot install the OpenSSH client ($_gaps)"
        ;;
    esac
    # Re-probe rather than trust the package manager: only the probes know whether the
    # binaries now on PATH can do the work.
    _gaps=$(openssh_gaps)
    [ -z "$_gaps" ] ||
        err "OpenSSH is still not usable after installing the packages: $_gaps. Install the named package by hand and re-run the installer"
    log "OpenSSH client ready (ssh, ssh-keygen and ssh-keyscan all work)"
}

# Stock wget is uclient-fetch, and uclient-fetch does TLS through a SEPARATE package:
# /lib/libustream-ssl.so, shipped by one of libustream-wolfssl / libustream-openssl /
# libustream-mbedtls (suffixed with the ABI date on 19.07: libustream-wolfssl20150806).
# Without it uclient-fetch still parses a URL, still lists --no-check-certificate in its help -
# and then fails the only request that matters:
#
#   wget: SSL support not available, please install one of the libustream-.*[ssl|tls] packages
#
# Measured: 19.07.10 ships no libustream at all; 22.03.7 / 23.05.5 / 24.10.1 / SNAPSHOT do.
# On 19.07, "opkg install libustream-wolfssl" (the UNVERSIONED name) resolves to the
# versioned package and makes https work - measured, and true on 22.03 through SNAPSHOT too,
# so the unversioned name is used first and a glob is the fallback rather than the reverse.
#
# This cannot rescue the panel-minted command itself (that fetch runs before this file is
# downloaded), so the installer only guarantees the same capability for everything it starts:
# the exchange over https and, more importantly, the heartbeat that runs forever afterwards.
# 0 when https will fail because the fetcher has no TLS library behind it, i.e. when there is
# something to install. Returns 1 (nothing to do) for plain http, for fetchers that link their
# own TLS, and - importantly - when a libustream variant is ALREADY installed: images ship
# libustream-mbedtls, and installing libustream-wolfssl next to it is a file clash, not an
# improvement.
needs_tls_lib() {
    case "${TG_PANEL_URL:-}" in
    https://*) ;;
    *) return 1 ;; # plain http needs no certificate at all
    esac
    case "$FETCHER" in
    wget) ;;
    # curl and GNU wget link their own TLS; uclient-fetch does not. Only wget is in question,
    # and only because on OpenWrt wget IS uclient-fetch.
    *) return 1 ;;
    esac
    for _tls_dir in $TLS_LIB_DIRS; do
        if [ -r "$_tls_dir/libustream-ssl.so" ]; then
            return 1 # a TLS-capable libustream is already there; any variant is enough
        fi
    done
    return 0
}

ensure_tls_lib() {
    needs_tls_lib || return 0
    # Only reachable when the panel URL is https, the fetcher is uclient-fetch and the
    # library is absent - i.e. the one state measured on 19.07.
    _tls_pkg=$(detect_pkg_manager)
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: uclient-fetch has no TLS support; would install libustream via $_tls_pkg"
        return 0
    fi
    log "wget on this router is uclient-fetch without a TLS package: installing libustream so https works"
    case "$_tls_pkg" in
    opkg)
        mkdir -p /var/lock /var/run 2>/dev/null || true
        run_cmd opkg update || log "warning: opkg update failed, trying the install anyway"
        # Unversioned first: it resolves on 19.07 (20150806) and on 21.02+ (20201210).
        if ! run_cmd opkg install libustream-wolfssl; then
            _tls_name=$(opkg list 2>/dev/null | sed -n 's/^\(libustream-[a-z]*\)[0-9].*/\1/p' | head -n 1)
            if [ -n "$_tls_name" ]; then
                run_cmd opkg install "$_tls_name" ||
                    log "warning: could not install $_tls_name"
            else
                log "warning: opkg offers no libustream package; https will not work on this image"
            fi
        fi
        ;;
    apk)
        run_cmd apk add --no-cache libustream-wolfssl ||
            log "warning: could not install libustream-wolfssl"
        ;;
    *)
        log "warning: no apk or opkg found; cannot install a TLS package for uclient-fetch"
        ;;
    esac
    if needs_tls_lib; then
        err "wget on this router still has no TLS support, so ${TG_PANEL_URL:-the panel} cannot be reached over https: install one of the libustream-*ssl packages (opkg install libustream-wolfssl, which is libustream-wolfssl20150806 on 19.07) and re-run. Alternatively set the panel agent endpoint to http"
    fi
}

# 0 when this router's TLS stack probably CANNOT validate a certificate chain, whatever
# tls_verify says. MEASURED for one generation, inferred for the rest - do not overclaim:
#   * on 19.07.10 with libustream-wolfssl20150806 + ca-bundle installed, uclient-fetch ACCEPTS a
#     self-signed certificate (it fetched our self-signed test panel and answered 401, where
#     21.02.7, 22.03.7, 23.05.5 and 24.10.1 all answer "Connection error: Invalid SSL
#     certificate"), while a hostname mismatch IS still caught;
#   * only the wolfssl libustream variant was measured, and early 21.02 point releases had
#     verification regressions of their own, so "major >= 21 is therefore safe" is NOT proven -
#     it is merely the oldest generation on which no failure was observed.
# So the gate below is "19.07-generation (major < 21) cannot verify", not "21.02+ always can".
#
# Fail CLOSED on a version it cannot parse (TLS_UNPARSED_RELEASE=1, warned about by the caller):
# an unknown release must never be treated as a modern one.
tls_stack_cannot_verify() {
    case "$FETCHER" in
    wget) ;;
    *) return 1 ;; # curl links its own SSL and does validate
    esac
    _rel=$(detect_openwrt_version)
    _major=${_rel%%.*}
    # Require the whole major component to be digits. "[0-9]*" also matches "19x", and the
    # numeric test then returns 2 - which, inside an "if", reads as "safe" (fail open).
    case "$_major" in
    "" | *[!0-9]*)
        # The version could not be parsed, so nothing is known - and an unknown release must
        # never be treated as a modern one. The flag lets the caller say WHY, instead of claiming
        # a release number it does not have.
        TLS_UNPARSED_RELEASE=1
        return 0
        ;;
    esac
    [ "$_major" -lt 21 ]
}

# --------------------------------------------------------------------------------------
# router metadata
# --------------------------------------------------------------------------------------
detect_hostname() {
    uname -n 2>/dev/null | tr -cd 'a-zA-Z0-9._-' | cut -c1-128
}

detect_model() {
    if [ -r /tmp/sysinfo/model ]; then
        head -n 1 /tmp/sysinfo/model | tr -cd 'a-zA-Z0-9 ._()/+-' | cut -c1-128
    fi
}

detect_openwrt_version() {
    if [ -r "$OPENWRT_RELEASE_FILE" ]; then
        sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" "$OPENWRT_RELEASE_FILE" | head -n 1 | cut -c1-64
    fi
}

detect_uptime() {
    _up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
    case "$_up" in
    '' | *[!0-9]*) _up=0 ;;
    esac
    printf '%s' "$_up"
}

# First physical interface: br-lan, then eth0/wan, then any non-virtual one.
detect_mac() {
    for _if in br-lan eth0 wan lan1; do
        if [ -r "/sys/class/net/$_if/address" ]; then
            cat "/sys/class/net/$_if/address"
            return 0
        fi
    done
    for _path in /sys/class/net/*/address; do
        [ -r "$_path" ] || continue
        _if=$(basename "$(dirname "$_path")")
        case "$_if" in
        lo | docker* | veth* | tun* | tap* | waydroid* | br-*) continue ;;
        esac
        _mac=$(cat "$_path")
        case "$_mac" in
        00:00:00:00:00:00) continue ;;
        esac
        printf '%s' "$_mac"
        return 0
    done
}

# json_quote <value>: JSON string literal without jq.
json_quote() {
    printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r\t')"
}
# --------------------------------------------------------------------------------------
# Embedded helpers. The panel serves this one file, so the JSON reader and the two
# supervised scripts are inlined here and materialised on the router. They are byte-identical
# to agent/lib/*.sh in the repository (tests/test_installer.py asserts that).
# --------------------------------------------------------------------------------------
write_json_lib() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write $JSON_LIB (JSON reader)"
        return 0
    fi
    mkdir -p "$STATE_DIR" || err "cannot create $STATE_DIR"
    cat >"$JSON_LIB" <<'TG_EOF_JSON' || err "cannot write $JSON_LIB (out of space?)"
#!/bin/sh
# TunnelGate - minimal JSON reader for busybox ash.
#
# Why not jq: OpenWrt does not ship jq, and the router must not download a JSON engine just
# to read one bootstrap response. Python is not guaranteed either. So this is a small
# recursive-descent JSON parser written in POSIX awk (busybox awk included) - it understands
# objects, arrays, strings with escapes (\n \t \r \" \\ \/ \b \f \uXXXX) and the
# number/true/false/null literals.
#
# API
#   json_get <dotted.path> [file]     print the decoded value, exit 0
#   json_has <dotted.path> [file]     exit 0 when the path exists (even if empty)
#
# Examples
#   json_get private_key /tmp/exchange.json    # real newlines, exact PEM text
#   json_get console.console_port /tmp/hb.json
#   json_get tunnel.remote_port
#
# Arrays are addressed by index: items.0.name
#
# Limitation that matters: \uXXXX above U+007F becomes '?'. Every field we read (hostnames,
# ports, PEM material, base64 keys) is ASCII, and silently emitting broken UTF-8 into an
# authorized_keys file would be worse than a visible replacement character.

# json_get <key> [file] -> stdout
json_get() {
    _json_key=${1:-}
    _json_file=${2:-${TG_JSON_FILE:-/tmp/tunnelgate-response.json}}
    [ -n "$_json_key" ] || return 2
    [ -r "$_json_file" ] || return 2
    awk -v want="$_json_key" '
        function jerr(msg) { ERR = msg; return 0 }

        function jskip(   c) {
            while (jp <= jlen) {
                c = substr(j, jp, 1)
                if (c == " " || c == "\t" || c == "\n" || c == "\r") jp++
                else break
            }
        }

        function jhex4(h,   i, c, v) {
            v = 0
            for (i = 1; i <= 4; i++) {
                c = tolower(substr(h, i, 1))
                if (c >= "0" && c <= "9") v = v * 16 + (c + 0)
                else if (c >= "a" && c <= "f") v = v * 16 + (index("abcdef", c) + 9)
                else return -1
            }
            return v
        }

        # Parse a JSON string at jp (which points at the opening quote).
        function jstring(   out, c, e, code) {
            jp++
            out = ""
            while (jp <= jlen) {
                c = substr(j, jp, 1)
                if (c == "\"") { jp++; SGVAL = out; return 1 }
                if (c != "\\") { out = out c; jp++; continue }
                e = substr(j, jp + 1, 1)
                jp += 2
                if (e == "n") out = out "\n"
                else if (e == "t") out = out "\t"
                else if (e == "r") out = out "\r"
                else if (e == "b") out = out "\b"
                else if (e == "f") out = out "\f"
                else if (e == "/" || e == "\\" || e == "\"") out = out e
                else if (e == "u") {
                    code = jhex4(substr(j, jp, 4))
                    jp += 4
                    if (code < 0) out = out "?"
                    else if (code < 128) out = out sprintf("%c", code)
                    else out = out "?"
                } else out = out e
            }
            return jerr("unterminated string")
        }

        function jvalue(path,   c, key, p, n, start, v) {
            jskip()
            if (jp > jlen) return jerr("unexpected end of input")
            c = substr(j, jp, 1)
            if (c == "{") {
                jp++; jskip()
                if (substr(j, jp, 1) == "}") { jp++; return 1 }
                while (jp <= jlen) {
                    jskip()
                    if (substr(j, jp, 1) != "\"") return jerr("expected object key")
                    if (!jstring()) return 0
                    key = SGVAL
                    jskip()
                    if (substr(j, jp, 1) != ":") return jerr("expected colon")
                    jp++
                    p = (path == "" ? key : path "." key)
                    if (!jvalue(p)) return 0
                    jskip()
                    c = substr(j, jp, 1)
                    if (c == ",") { jp++; continue }
                    if (c == "}") { jp++; return 1 }
                    return jerr("expected , or }")
                }
                return jerr("unterminated object")
            }
            if (c == "[") {
                jp++; jskip()
                if (substr(j, jp, 1) == "]") { jp++; return 1 }
                n = 0
                while (jp <= jlen) {
                    if (!jvalue(path "." n)) return 0
                    n++
                    jskip()
                    c = substr(j, jp, 1)
                    if (c == ",") { jp++; continue }
                    if (c == "]") { jp++; return 1 }
                    return jerr("expected , or ]")
                }
                return jerr("unterminated array")
            }
            if (c == "\"") {
                if (!jstring()) return 0
                val[path] = SGVAL
                typ[path] = "string"
                return 1
            }
            start = jp
            while (jp <= jlen) {
                c = substr(j, jp, 1)
                if (c == "," || c == "}" || c == "]" || c == " " || c == "\n" || c == "\r" || c == "\t") break
                jp++
            }
            if (jp == start) return jerr("empty literal")
            v = substr(j, start, jp - start)
            val[path] = v
            typ[path] = "literal"
            return 1
        }

        { j = j $0 "\n" }
        END {
            jlen = length(j)
            jp = 1
            if (!jvalue("")) {
                printf "json parse error: %s\n", (ERR == "" ? "unknown" : ERR) > "/dev/stderr"
                exit 3
            }
            if (want in typ) {
                printf "%s", val[want]
                exit 0
            }
            exit 1
        }
    ' "$_json_file"
}

# json_has <key> [file] -> exit 0 when the path exists
json_has() {
    json_get "$@" >/dev/null 2>&1
}
TG_EOF_JSON
    chmod 0755 "$JSON_LIB"
}

write_loop_bin() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write $LOOP_BIN (reconnect loop)"
        return 0
    fi
    mkdir -p "$(dirname "$LOOP_BIN")" || err "cannot create $(dirname "$LOOP_BIN")"
    cat >"$LOOP_BIN" <<'TG_EOF_LOOP' || err "cannot write $LOOP_BIN (out of space?)"
#!/bin/sh
# TunnelGate router agent - reverse-tunnel supervisor loop.
#
# Why a loop and not autossh: autossh is another package to install and to keep working on
# top of a firmware upgrade, and it gives no control over the reconnect policy. procd already
# supervises processes; a plain loop with a fixed back-off covers "reconnect forever", keeps
# the failure modes visible in logread and needs no extra binary on the router.
#
# Installed by the panel-served agent/install.sh as /usr/bin/ssh-loop (mode 0755).
# Configuration is read from /etc/config/tunnelgate (UCI section "main"), so an operator can
# change ports or the panel host without re-running the installer.
#
# This script never prints, echoes or logs the private key: the key is only ever passed to
# ssh(1) through -i.

RETRY_SECONDS=10
DEFAULT_KEY=/root/.ssh/tunnelgate_ed25519
DEFAULT_KNOWN_HOSTS=/root/.ssh/known_hosts
CONFIG_FILE=${TG_CONFIG:-/etc/config/tunnelgate}

umask 077

# Private directory for ssh's stderr capture, created lazily on the first connection attempt.
#
# The file only ever holds ssh(1) diagnostics (host key warnings, "remote port forwarding
# failed", DNS errors) - no key material, no token - so this is not a credential fix. It is a
# symlink fix: "/tmp/tunnelgate-ssh-$$.log" with a predictable name let any local user pre-create
# it and have root truncate or append to a file of their choosing. The cost of closing that is
# one mktemp -d per reconnect.
TMP_DIR=""

make_tmp_dir() {
    [ -n "$TMP_DIR" ] && return 0
    TMP_DIR=$(umask 077; mktemp -d "${TMPDIR:-/tmp}/tunnelgate-ssh.$$.XXXXXX" 2>/dev/null) || {
        TMP_DIR=""
        return 1
    }
    chmod 0700 "$TMP_DIR" 2>/dev/null
}

cleanup() {
    [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR" 2>/dev/null
    TMP_DIR=""
}

# procd stops this process with SIGTERM: without a handler the trap on EXIT still fires under
# dash/busybox ash, but an explicit handler makes the intent readable.
on_signal() {
    cleanup
    trap - EXIT INT TERM
    exit 143
}

trap cleanup EXIT
trap on_signal INT TERM

log() {
    logger -t tunnelgate "$*" 2>/dev/null
    printf '[tunnelgate] %s\n' "$*" >&2
}

# cfg_get <option> -> value on stdout (empty when unset).
# Uses uci when it exists; falls back to a tiny parser so the script stays testable on a
# non-OpenWrt host (and so a corrupted /etc/config still yields a readable error).
cfg_get() {
    _tg_value=""
    if command -v uci >/dev/null 2>&1; then
        _tg_value=$(uci -q get "tunnelgate.main.$1" 2>/dev/null)
    else
        _tg_value=$(sed -n "s/^[[:space:]]*option[[:space:]]*$1[[:space:]]*'\(.*\)'[[:space:]]*\$/\1/p" \
            "$CONFIG_FILE" 2>/dev/null | head -n 1)
    fi
    printf '%s' "$_tg_value"
}

ssh_host=$(cfg_get ssh_host)
ssh_port=$(cfg_get ssh_port)
ssh_user=$(cfg_get ssh_user)
tunnel_port=$(cfg_get tunnel_port)
local_port=$(cfg_get local_port)
key_path=$(cfg_get key_path)
known_hosts=$(cfg_get known_hosts_path)
console_enabled=$(cfg_get console_enabled)
console_port=$(cfg_get console_port)
console_target_port=$(cfg_get console_target_port)

[ -n "$ssh_host" ] || {
    log "no ssh_host configured in $CONFIG_FILE, refusing to start"
    exit 1
}
[ -n "$tunnel_port" ] || {
    log "no tunnel_port configured in $CONFIG_FILE, refusing to start"
    exit 1
}
[ -n "$ssh_port" ] || ssh_port=22
[ -n "$ssh_user" ] || ssh_user=root
[ -n "$local_port" ] || local_port=80
[ -n "$key_path" ] || key_path=$DEFAULT_KEY
[ -n "$known_hosts" ] || known_hosts=$DEFAULT_KNOWN_HOSTS
[ -n "$console_target_port" ] || console_target_port=22

[ -r "$key_path" ] || {
    log "private key $key_path is missing or unreadable; re-run the installer"
    exit 1
}

log "agent starting (ssh $ssh_user@$ssh_host:$ssh_port, tunnel $tunnel_port -> 127.0.0.1:$local_port)"

while :; do
    # A private directory per reconnect; if it cannot be created, skip the capture rather than
    # fall back to a predictable path (the diagnostics are useful, not essential).
    if make_tmp_dir; then
        stderr_file="$TMP_DIR/ssh.log"
    else
        stderr_file=""
    fi
    if [ -n "$stderr_file" ]; then
        : >"$stderr_file"
    fi

    # One SSH connection carries BOTH reverse listeners. The panel authorizes exactly these
    # two ports on a single public key (one permitlisten per port), so a second connection
    # for the console would be rejected - and would double the supervised processes for no
    # gain. See agent/README.md ("console") for the trust model.
    set -- ssh -N -T \
        -i "$key_path" \
        -o BatchMode=yes \
        -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$known_hosts" \
        -o ConnectTimeout=20 \
        -o LogLevel=ERROR \
        -p "$ssh_port" \
        -R "127.0.0.1:$tunnel_port:127.0.0.1:$local_port"

    if [ "$console_enabled" = "1" ] && [ -n "$console_port" ]; then
        set -- "$@" -R "127.0.0.1:$console_port:127.0.0.1:$console_target_port"
        log "console listener enabled (127.0.0.1:$console_port -> 127.0.0.1:$console_target_port)"
    fi

    set -- "$@" "$ssh_user@$ssh_host"

    if [ -n "$stderr_file" ]; then
        "$@" 2>"$stderr_file"
    else
        "$@" 2>/dev/null
    fi
    rc=$?

    # ssh(1) diagnostics (host key mismatch, "remote port forwarding failed", DNS errors) are
    # the only useful text and contain no key material - forward them to syslog ourselves,
    # because the procd instance runs with stderr 0 to keep the log format uniform.
    if [ -n "$stderr_file" ] && [ -s "$stderr_file" ]; then
        log "ssh: $(tr '\n' ' ' <"$stderr_file" | cut -c1-400)"
    fi
    rm -f "$stderr_file"

    log "ssh exited rc=$rc, reconnecting in ${RETRY_SECONDS}s"
    sleep "$RETRY_SECONDS"
done
TG_EOF_LOOP
    chmod 0755 "$LOOP_BIN"
}

write_heartbeat_bin() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write $HB_BIN (heartbeat sender)"
        return 0
    fi
    mkdir -p "$(dirname "$HB_BIN")" || err "cannot create $(dirname "$HB_BIN")"
    cat >"$HB_BIN" <<'TG_EOF_HB' || err "cannot write $HB_BIN (out of space?)"
#!/bin/sh
# TunnelGate - heartbeat sender (procd instance "heartbeat", runs every 60 s).
#
# Responsibilities
#   * POST metadata to the panel so a quiet tunnel still proves the router is alive;
#   * adopt the heartbeat_url the panel puts in its "desired" payload, so a panel that moved
#     does not orphan routers that are already installed;
#   * consume the console key registration delivered in the response: when the serial in
#     UCI is behind the serial shipped by the panel, rewrite the tunnelgate-console line in
#     /etc/dropbear/authorized_keys, bump the stored serial and report console_installed.
#
# TLS: the panel connection is verified unless tls_verify is exactly "0" (a self-signed panel
# certificate). Only that option adds -k / --no-check-certificate.
#
# The console key pair is created lazily by the panel the first time an operator opens a
# console, so the installer cannot know the public half - this loop is the delivery channel.

CONFIG_FILE=${TG_CONFIG:-/etc/config/tunnelgate}
# The release file the capability check reads (overridable so a test can say "pretend 19.07").
OPENWRT_RELEASE_FILE=${TG_OPENWRT_RELEASE:-/etc/openwrt_release}
# The JSON reader is installed next to the other agent files; the installer writes
# its exact path into UCI (TG_LIB_DIR overrides it, for tests and odd layouts).
LIB_DIR=${TG_LIB_DIR:-}
CLIENT_VERSION="1.0"
DEFAULT_KEYS=${TG_KEYS:-/etc/dropbear/authorized_keys}
CONSOLE_MARK=tunnelgate-console

# Private working directory for this run. It is created LAZILY (only when something is actually
# written) with umask 077 and mode 0700, and removed on exit and on SIGTERM.
#
# Why not "/tmp/tunnelgate-heartbeat-body.$$": that file carries the API token in clear, and the
# name is predictable, so any local user can pre-create it as a symlink to a file they can read -
# or to one root can overwrite - and win the race. This process runs as root every 60 seconds, so
# it is the perfect target for exactly that. The pid in the old name made the race easy, not safe.
TMP_DIR=""
TMP_BODY=""
RESPONSE=""

# The fetcher is probed once, for the same reason as in install.sh: stock OpenWrt has no curl,
# and its uclient-fetch has no --header before 24.10.
FETCHER=""
if command -v curl >/dev/null 2>&1; then
    FETCHER=curl
elif command -v wget >/dev/null 2>&1; then
    FETCHER=wget
fi

umask 077

# make_tmp_dir: create the private directory on first use. mktemp -d refuses a path that already
# exists, which is what closes the symlink race; 0700 means another user cannot even list it.
make_tmp_dir() {
    [ -n "$TMP_DIR" ] && return 0
    TMP_DIR=$(umask 077; mktemp -d "${TMPDIR:-/tmp}/tunnelgate-hb.$$.XXXXXX" 2>/dev/null) || {
        TMP_DIR=""
        return 1
    }
    chmod 0700 "$TMP_DIR" 2>/dev/null
    TMP_BODY="$TMP_DIR/heartbeat.json"
    RESPONSE="$TMP_DIR/response.json"
}

# shellcheck disable=SC2329  # invoked from the traps below
cleanup() {
    if [ -n "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR" 2>/dev/null
    fi
    TMP_DIR=""
    TMP_BODY=""
    RESPONSE=""
}

# SIGTERM is how the init script stops this instance, so the exit path that removes the directory
# has to run on a signal too. Exit 143 = killed by SIGTERM, the conventional value.
# shellcheck disable=SC2329  # invoked from the traps below
on_signal() {
    cleanup
    trap - EXIT INT TERM
    exit 143
}

trap cleanup EXIT
trap on_signal INT TERM


log() {
    logger -t tunnelgate "$*" 2>/dev/null
    printf '[tunnelgate] %s\n' "$*" >&2
}

cfg_get() {
    _tg_value=""
    if command -v uci >/dev/null 2>&1; then
        _tg_value=$(uci -q get "tunnelgate.main.$1" 2>/dev/null)
    else
        _tg_value=$(sed -n "s/^[[:space:]]*option[[:space:]]*$1[[:space:]]*'\(.*\)'[[:space:]]*\$/\1/p" \
            "$CONFIG_FILE" 2>/dev/null | head -n 1)
    fi
    printf '%s' "$_tg_value"
}

# The JSON reader lives in one place: /usr/lib/tunnelgate/json.sh (installed by install.sh,
# same file as agent/lib/json.sh in the repo, which tests/test_installer.py exercises).
if [ -z "$LIB_DIR" ]; then
    LIB_DIR=/usr/lib/tunnelgate
    _cfg_lib=$(cfg_get json_lib)
    if [ -n "$_cfg_lib" ]; then
        LIB_DIR=$(dirname "$_cfg_lib")
    fi
fi

if [ -r "$LIB_DIR/json.sh" ]; then
    . "$LIB_DIR/json.sh"
else
    # Without the reader a console registration cannot be consumed; the heartbeat
    # itself still works, so this is a warning rather than a fatal error.
    log "warning: $LIB_DIR/json.sh is missing, console key registration disabled"
    json_get() { return 2; }
fi

# TLS policy for the panel connection (see docs/INSTALL_ROUTER.md).
#
# TG_TLS_VERIFY wins when the installer started this process; at runtime the UCI option the
# installer wrote is the source of truth, so 'uci set tunnelgate.main.tls_verify=0' plus
# '/etc/init.d/tunnelgate restart' changes the behaviour without re-installing.
#
# ONLY the exact string "0" disables verification: "1", "yes", "2", "false", "" and anything
# else mean VERIFY, because a value we do not understand must not downgrade the connection that
# carries the API token.
TLS_VERIFY=1
_tls_value=${TG_TLS_VERIFY:-}
if [ -z "$_tls_value" ]; then
    _tls_value=$(cfg_get tls_verify)
fi
if [ "$_tls_value" = "0" ]; then
    TLS_VERIFY=0
fi

# Same capability question as in install.sh, and the same honest answer: MEASURED for the
# 19.07 generation (uclient-fetch there accepts a self-signed certificate; a wrong hostname is
# still caught), NOT proven safe for every 21.02+ point release, and unparsable versions are
# treated as unverified rather than as modern. Returns 0 when the chain probably is not checked.
# Do NOT use it to refuse the heartbeat: the installer already refuses a fresh install on such a
# stack, and a router installed before that check must not silently lose its liveness signal.
# This process only NAGS, once per boot.
tls_stack_cannot_verify() {
    [ "$FETCHER" = "wget" ] || return 1 # curl links its own SSL and does validate
    _rel=""
    if [ -r "$OPENWRT_RELEASE_FILE" ]; then
        _rel=$(sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" "$OPENWRT_RELEASE_FILE" | head -n 1)
    fi
    _major=${_rel%%.*}
    # "[0-9]*" also matches "19x" and the numeric test then returns 2, which reads as "safe".
    case "$_major" in
    "" | *[!0-9]*) return 0 ;;
    esac
    [ "$_major" -lt 21 ]
}

cfg_set() {
    if command -v uci >/dev/null 2>&1; then
        uci -q set "tunnelgate.main.$1=$2" && uci -q commit tunnelgate
        return $?
    fi
    # Fallback for a host without uci (test suite, or a stripped image): rewrite the option in
    # place so the serial really is persisted and the next heartbeat does not reinstall the same
    # console key forever.
    #
    # NO sed here. The value goes into a sed REPLACEMENT, where & means "the whole match",
    # \1 is a backreference and the delimiter (whatever it is) terminates the expression - so a
    # URL with a query string (&) or a value containing | or \ corrupted or broke the rewrite,
    # silently, on the one path that exists precisely for hosts where nothing else works. awk
    # takes the value as DATA, so nothing in it is special.
    [ -r "$CONFIG_FILE" ] || return 1
    _tmp="$CONFIG_FILE.tg-new.$$"
    TG_OPT_NAME=$1 TG_OPT_VALUE=$2 awk '
        BEGIN { name = ENVIRON["TG_OPT_NAME"]; value = ENVIRON["TG_OPT_VALUE"]; done = 0 }
        {
            # Match the option line by its second field, so a value that looks like an option is
            # not mistaken for one.
            if (!done && $1 == "option" && $2 == name) {
                printf "\toption %s \047%s\047\n", name, value
                done = 1
                next
            }
            print
        }
        END { if (!done) printf "\toption %s \047%s\047\n", name, value }
    ' "$CONFIG_FILE" >"$_tmp" 2>/dev/null || {
        rm -f "$_tmp"
        return 1
    }
    chmod 0600 "$_tmp" && mv "$_tmp" "$CONFIG_FILE"
}

# json_quote <value> -> JSON string literal (no jq on OpenWrt).
json_quote() {
    printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n\r\t')"
}

# post <url> <token> <body-file> <output-file> -> HTTP status on stdout ("" when unreachable)
post() {
    _tg_url=$1
    _tg_token=$2
    _tg_body=$3
    _tg_out=$4

    rm -f "$_tg_out" 2>/dev/null

    case "$FETCHER" in
    curl)
        # -k only when tls_verify is exactly 0; there is no global switch.
        _tg_k=""
        if [ "$TLS_VERIFY" = "0" ]; then
            _tg_k="-k"
        fi
        # NO credential on the command line: -H and -u both expose the API token in
        # /proc/PID/cmdline to every local user, and this process starts again every 60 s. The
        # body already carries api_token, and the panel accepts it there (which is also the only
        # channel a pre-24.10 uclient-fetch has). Verified against the live panel with a
        # body-only POST.
        _tg_code=$(curl -q -sS ${_tg_k:+"$_tg_k"} -o "$_tg_out" -w '%{http_code}' --max-time 30 -X POST \
            -H "Content-Type: application/json" \
            --data-binary "@$_tg_body" \
            "$_tg_url" 2>/dev/null)
        case "$_tg_code" in
        000 | "") return 0 ;;
        *)
            printf '%s' "$_tg_code"
            return 0
            ;;
        esac
        ;;
    wget)
        _tg_err="$_tg_out.err.$$"
        _tg_ncc=""
        if [ "$TLS_VERIFY" = "0" ]; then
            _tg_ncc="--no-check-certificate"
        fi
        wget -O "$_tg_out" ${_tg_ncc:+"$_tg_ncc"} --post-file="$_tg_body" --timeout=30 "$_tg_url" 2>"$_tg_err"
        _tg_rc=$?
        _tg_code=$(sed -n \
            -e 's/.*HTTP error \([0-9][0-9][0-9]\).*/\1/p' \
            -e 's/.*awaiting response\.\.\. \([0-9][0-9][0-9]\).*/\1/p' \
            -e 's/.*ERROR \([0-9][0-9][0-9]\).*/\1/p' \
            "$_tg_err" 2>/dev/null | tail -n 1)
        rm -f "$_tg_err"
        if [ -n "$_tg_code" ]; then
            printf '%s' "$_tg_code"
            return 0
        fi
        [ "$_tg_rc" = "0" ] && printf '200'
        return 0
        ;;
    esac
    return 1
}

# send_heartbeat [console_installed_flag] -> prints HTTP status
send_heartbeat() {
    _hostname=$(uname -n 2>/dev/null)
    _model=""
    [ -r /tmp/sysinfo/model ] && _model=$(head -n 1 /tmp/sysinfo/model)
    _openwrt=""
    if [ -r "$OPENWRT_RELEASE_FILE" ]; then
        _openwrt=$(sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" "$OPENWRT_RELEASE_FILE" | head -n 1)
    fi
    _uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)
    [ -n "$_uptime" ] || _uptime=0
    # Nothing below can work without the private directory, and a credential must never be
    # written to a path this process did not create itself.
    make_tmp_dir || {
        log "cannot create a private temporary directory under ${TMPDIR:-/tmp}; refusing to write the API token to a predictable path"
        return 2
    }
    {
        printf '{"hostname":%s' "$(json_quote "$_hostname")"
        printf ',"model":%s' "$(json_quote "$_model")"
        printf ',"openwrt_version":%s' "$(json_quote "$_openwrt")"
        printf ',"uptime_seconds":%s' "$_uptime"
        printf ',"client_version":%s' "$(json_quote "$CLIENT_VERSION")"
        [ "$1" = "1" ] && printf ',"console_installed":true'
        # The credential in the body: the only channel a pre-24.10 uclient-fetch can use.
        printf ',"api_token":%s' "$(json_quote "$api_token")"
        printf '}\n'
    } >"$TMP_BODY"

    post "$heartbeat_url" "$api_token" "$TMP_BODY" "$RESPONSE"
}

heartbeat_url=$(cfg_get heartbeat_url)
api_token=$(cfg_get api_token)
console_enabled=$(cfg_get console_enabled)
keys_path=$(cfg_get console_authorized_keys_path)
[ -n "$keys_path" ] || keys_path=$DEFAULT_KEYS

if [ -z "$heartbeat_url" ] || [ -z "$api_token" ]; then
    log "heartbeat disabled: heartbeat_url or api_token missing in $CONFIG_FILE"
    exit 0
fi

if [ -z "$FETCHER" ]; then
    log "heartbeat disabled: neither curl nor wget is installed, so $heartbeat_url cannot be reached"
    exit 0
fi

# One warning per boot, not one per minute: this process is restarted every 60 s and a warning
# that shouts every minute is a warning nobody reads.
if [ "$TLS_VERIFY" = "0" ]; then
    # The marker file is EMPTY and its name is the whole message: it carries no URL, no token and
    # nothing else that would be worth keeping private, which is why these two stay in /tmp while
    # everything that held a credential moved into the private directory.
    _tls_warned=${TG_TLS_WARN_FILE:-/tmp/.tunnelgate-tls-warning}
    if [ ! -e "$_tls_warned" ]; then
        log "WARNING: TLS certificate verification is OFF for $heartbeat_url (tunnelgate.main.tls_verify=0). Anyone who can answer for that host receives the API token. Restore it with: uci set tunnelgate.main.tls_verify=1 && uci commit tunnelgate && /etc/init.d/tunnelgate restart"
        : >"$_tls_warned" 2>/dev/null
    fi
fi

# The 19.07-generation nag. Separate marker file from the tls_verify=0 warning: they describe
# different situations and one must not suppress the other.
if [ "$TLS_VERIFY" = "1" ] && tls_stack_cannot_verify; then
    _cap_warned=${TG_TLS_CAP_WARN_FILE:-/tmp/.tunnelgate-tls-capability-warning}
    if [ ! -e "$_cap_warned" ]; then
        log "WARNING: this router's OpenWrt release cannot check a certificate chain (measured on the 19.07 generation: such a fetcher accepts a self-signed certificate), so the panel at $heartbeat_url is not authenticated even though tls_verify=1. The API token is only as safe as the path to the panel. OpenWrt 21.02 or newer verifies a chain; if the panel uses a self-signed certificate, turn the check off in Settings > Agent endpoint so the acknowledgement is recorded"
        : >"$_cap_warned" 2>/dev/null
    fi
fi

# Create the directory in THIS shell, not inside send_heartbeat: that runs in a $(...) subshell,
# so a directory created only there would leave RESPONSE empty in the parent and every
# json_get "$RESPONSE" below would read nothing. make_tmp_dir is idempotent, so the guard inside
# send_heartbeat still covers a direct call.
if ! make_tmp_dir; then
    log "cannot create a private temporary directory under ${TMPDIR:-/tmp}; refusing to write the API token to a predictable path"
    exit 1
fi

http_code=$(send_heartbeat 0)
case "$http_code" in
2??) ;;
"") log "heartbeat failed: no HTTP status (DNS, TLS or network problem)"; exit 0 ;;
*) log "heartbeat failed: HTTP $http_code"; exit 0 ;;
esac

# --- desired state ------------------------------------------------------------------------
# The panel can move (new hostname, TLS terminating in front, another port). An installed
# router cannot be re-installed from here, so the heartbeat response carries the address it
# should use from now on; adopting it is what keeps a fleet alive across a panel move.
desired_url=$(json_get desired.heartbeat_url "$RESPONSE")
if [ -n "$desired_url" ] && [ "$desired_url" != "$heartbeat_url" ]; then
    case "$desired_url" in
    http://* | https://*)
        if cfg_set heartbeat_url "$desired_url"; then
            log "panel moved: heartbeat_url updated to $desired_url"
        else
            log "panel moved to $desired_url but UCI could not be updated"
        fi
        ;;
    *) log "ignoring desired heartbeat_url '$desired_url': not an http(s) URL" ;;
    esac
fi

# --- console key registration -------------------------------------------------------------
# Only when the panel enabled the console for this router; otherwise this is a no-op.
[ "$console_enabled" = "1" ] || exit 0

new_serial=$(json_get console.serial "$RESPONSE")
[ -n "$new_serial" ] || exit 0
[ "$new_serial" -gt 0 ] 2>/dev/null || exit 0
stored_serial=$(cfg_get console_serial)
[ -n "$stored_serial" ] || stored_serial=0
if ! [ "$new_serial" -gt "$stored_serial" ] 2>/dev/null; then
    exit 0
fi

public_key=$(json_get console.public_key "$RESPONSE")
if [ -z "$public_key" ]; then
    log "console registration serial=$new_serial carries no public key, ignoring"
    exit 0
fi
console_user=$(json_get console.user "$RESPONSE")
[ -n "$console_user" ] || console_user=root
allowed_from=$(json_get console.allowed_from "$RESPONSE")
[ -n "$allowed_from" ] || allowed_from=127.0.0.1
# The panel always sends /etc/dropbear/authorized_keys, which dropbear only reads for root. A
# NON-root console account needs its own ~/.ssh/authorized_keys, so that file wins over the one
# in the response whenever UCI names a non-root user: the installer decided this at install time
# and wrote the effective path into UCI, and the panel's constant must not undo it.
reg_keys_path=$(cfg_get console_authorized_keys_path)
if [ -z "$reg_keys_path" ]; then
    reg_keys_path=$(json_get console.authorized_keys_path "$RESPONSE")
fi
[ -n "$reg_keys_path" ] || reg_keys_path=$keys_path

key_type=$(printf '%s' "$public_key" | awk '{print $1}')
key_body=$(printf '%s' "$public_key" | awk '{print $2}')
if [ -z "$key_body" ]; then
    log "console registration serial=$new_serial carries a malformed public key, ignoring"
    exit 0
fi
[ -n "$key_type" ] || key_type=ssh-ed25519

# The pty restriction is intentionally absent: an interactive shell is the whole point of
# this key. Port/agent/X11 forwarding stay denied; from= pins the panel's source address.
line="from=\"$allowed_from\",no-port-forwarding,no-agent-forwarding,no-X11-forwarding $key_type $key_body $CONSOLE_MARK"

mkdir -p "$(dirname "$reg_keys_path")" 2>/dev/null
touch "$reg_keys_path" 2>/dev/null
chmod 700 "$(dirname "$reg_keys_path")" 2>/dev/null
chmod 600 "$reg_keys_path" 2>/dev/null

# Rewrite atomically (temp file + rename): a half-written authorized_keys would lock the
# operator out of dropbear, which is exactly the state nobody can debug remotely.
tmp_keys="$reg_keys_path.tg-new.$$"
if [ -r "$reg_keys_path" ]; then
    grep -v " $CONSOLE_MARK\$" "$reg_keys_path" >"$tmp_keys" 2>/dev/null
else
    : >"$tmp_keys"
fi
printf '%s\n' "$line" >>"$tmp_keys"
chmod 600 "$tmp_keys"
if mv "$tmp_keys" "$reg_keys_path" 2>/dev/null; then
    log "console key installed for user $console_user (serial $new_serial)"
    cfg_set console_serial "$new_serial" || log "could not persist console_serial in UCI"
else
    log "failed to install console key into $reg_keys_path"
    rm -f "$tmp_keys"
    exit 0
fi

# Tell the panel the key is in place (sets Router.console_installed_at). HeartbeatIn does not
# declare console_installed, so the panel reads the flag off the raw request body; a second
# heartbeat is the only way to signal "installed" after the first one delivered the key.
http_code=$(send_heartbeat 1)
case "$http_code" in
2??) ;;
*) log "console_installed report failed: HTTP ${http_code:-none}" ;;
esac
exit 0
TG_EOF_HB
    chmod 0755 "$HB_BIN" || err "cannot chmod $HB_BIN"
    log "heartbeat sender written to $HB_BIN"
}


write_uninstall_bin() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write $UNINSTALL_BIN (uninstaller)"
        return 0
    fi
    mkdir -p "$(dirname "$UNINSTALL_BIN")" || err "cannot create $(dirname "$UNINSTALL_BIN")"
    cat >"$UNINSTALL_BIN" <<'TG_EOF_UNINSTALL' || err "cannot write $UNINSTALL_BIN (out of space?)"
#!/bin/sh
# TunnelGate router agent - uninstaller (OpenWrt, POSIX sh / busybox ash).
#
# Installed by the panel-served agent/install.sh as /usr/bin/tunnelgate-uninstall, so an
# operator can remove the agent without downloading the installer again:
#
#   /etc/init.d/tunnelgate stop ; tunnelgate-uninstall
#
# It removes exactly what the installer created and nothing else: the init script, the UCI
# config, the two supervisor scripts, the state directory, the private key, and ONE line of
# /etc/dropbear/authorized_keys (the one carrying the tunnelgate-console comment). Keys that
# belong to somebody else in that file are left alone.
#
# The router record on the panel is NOT touched: delete it there to release the port and to
# drop the router key line from the panel authorized_keys.
#
# Every path can be redirected with a TG_* variable (the defaults are the real OpenWrt paths)
# so tests/test_installer.py can drive this script without touching /etc or /root.

set -u

CONFIG=${TG_CONFIG:-/etc/config/tunnelgate}
INITD=${TG_INITD:-/etc/init.d/tunnelgate}
LOOP_BIN=${TG_LOOP_BIN:-/usr/bin/ssh-loop}
HB_BIN=${TG_HB_BIN:-/usr/bin/tunnelgate-heartbeat}
SELF_BIN=${TG_UNINSTALL_BIN:-/usr/bin/tunnelgate-uninstall}
STATE_DIR=${TG_STATE_DIR:-/usr/lib/tunnelgate}
KEY_PATH=${TG_KEY_PATH:-/root/.ssh/tunnelgate_ed25519}
CONSOLE_MARK=tunnelgate-console
# Exactly the set agent/install.sh installs (same spelling there, so the two can be diffed).
# openssh-client alone is NOT enough - see the measurement table in agent/install.sh.
OPENSSH_PKGS="openssh-client openssh-keygen openssh-client-utils"

DRY_RUN=0
PURGE=0

log() {
    logger -t tunnelgate "$*" 2>/dev/null
    printf '[tunnelgate] %s\n' "$*"
}

err() {
    log "error: $*"
    exit 1
}

usage() {
    cat <<'USAGE'
TunnelGate router agent uninstaller.

  Usage: tunnelgate-uninstall [--purge] [--dry-run]

    --purge      also remove openssh-client, openssh-keygen, openssh-client-utils and the
                 dedicated console user
    --dry-run    print what would be removed, change nothing

  Requires root. Removes the init script, the UCI config, the supervisor scripts, the state
  directory, the private key and our console key line. Keys belonging to other operators in
  /etc/dropbear/authorized_keys are kept.

  The router record on the panel is not touched: delete it in the panel as well.
USAGE
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
        --purge) PURGE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --help | -h)
            usage
            exit 0
            ;;
        *) err "unknown argument: $1 (try --help)" ;;
        esac
        shift
    done
}

# cfg_get <option> -> value on stdout (empty when the config is absent or the key is unset).
# uci(1) when it exists, otherwise the same tiny parser the installer and the agent use.
cfg_get() {
    _tg_value=""
    [ -f "$CONFIG" ] || {
        printf '%s' ""
        return 0
    }
    if command -v uci >/dev/null 2>&1; then
        _tg_value=$(uci -q get "tunnelgate.main.$1" 2>/dev/null)
    else
        _tg_value=$(sed -n "s/^[[:space:]]*option[[:space:]]*$1[[:space:]]*'\(.*\)'[[:space:]]*$/\1/p" \
            "$CONFIG" 2>/dev/null | head -n 1)
    fi
    printf '%s' "$_tg_value"
}

stop_service() {
    if [ ! -x "$INITD" ]; then
        log "no init script at $INITD (nothing to stop)"
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would stop and disable $INITD"
        return 0
    fi
    if [ "${TG_SKIP_SERVICE:-0}" = "1" ]; then
        log "TG_SKIP_SERVICE=1: leaving the init system alone"
        return 0
    fi
    # Stop before disable: a disabled-but-running procd instance keeps reconnecting.
    "$INITD" stop >/dev/null 2>&1
    "$INITD" disable >/dev/null 2>&1
    log "service stopped and disabled"
}

delete_console_key() {
    _keys=${TG_KEYS:-/etc/dropbear/authorized_keys}
    _cfg_keys=$(cfg_get console_authorized_keys_path)
    [ -n "$_cfg_keys" ] && _keys="$_cfg_keys"

    if [ ! -f "$_keys" ]; then
        log "no $_keys (no console key to remove)"
        return 0
    fi
    if ! grep -q " $CONSOLE_MARK$" "$_keys" 2>/dev/null; then
        log "no $CONSOLE_MARK line in $_keys"
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would remove the $CONSOLE_MARK line from $_keys"
        return 0
    fi

    # Only our line goes. A temp file plus rename keeps the file consistent if the router
    # loses power mid-uninstall, and restores the 0600 mode dropbear insists on.
    _tmp="$_keys.tunnelgate-new.$$"
    if grep -v " $CONSOLE_MARK$" "$_keys" >"$_tmp" 2>/dev/null &&
        chmod 0600 "$_tmp" &&
        mv "$_tmp" "$_keys"; then
        log "removed the $CONSOLE_MARK line from $_keys"
    else
        rm -f "$_tmp"
        log "warning: could not rewrite $_keys; remove the $CONSOLE_MARK line by hand"
    fi
}

delete_console_user() {
    _user=$(cfg_get console_user)
    # Only an account the INSTALLER created is removed. A pre-existing account is somebody's
    # login, and --purge must never delete it - it was not ours to remove. The installer records
    # this in UCI precisely so the two uninstallers can agree without guessing.
    _created=$(cfg_get console_user_created)
    case "$_user" in
    "" | root) return 0 ;;
    esac
    if [ "$_created" != "1" ]; then
        log "keeping console user $_user: the installer did not create it"
        return 0
    fi
    id -u "$_user" >/dev/null 2>&1 || return 0
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would remove the console user $_user"
        return 0
    fi
    deluser "$_user" >/dev/null 2>&1 || log "warning: could not remove console user $_user"
}

delete_files() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would remove $INITD $CONFIG $LOOP_BIN $HB_BIN $SELF_BIN"
        log "dry-run: would remove $STATE_DIR and $KEY_PATH"
        return 0
    fi

    rm -f "$INITD" "$CONFIG" "$LOOP_BIN" "$HB_BIN"
    rm -rf "$STATE_DIR"
    rm -f "$KEY_PATH"
    # Report files the exchange and the heartbeat leave behind in /tmp.
    rm -f /tmp/tunnelgate-exchange.* /tmp/tunnelgate-report.* /tmp/tunnelgate-heartbeat-* 2>/dev/null

    # Remove this script last: a failure above still leaves the operator a working --dry-run.
    rm -f "$SELF_BIN"
}

delete_package() {
    # Best effort, one package at a time: a package that was never installed is not an error,
    # and a failed removal is logged instead of aborting the purge halfway through.
    if command -v apk >/dev/null 2>&1; then
        for _pkg in $OPENSSH_PKGS; do
            log "removing $_pkg via apk"
            apk del "$_pkg" >/dev/null 2>&1 || log "warning: apk could not remove $_pkg"
        done
    elif command -v opkg >/dev/null 2>&1; then
        for _pkg in $OPENSSH_PKGS; do
            log "removing $_pkg via opkg"
            opkg remove "$_pkg" >/dev/null 2>&1 || log "warning: opkg could not remove $_pkg"
        done
    else
        log "no apk or opkg found; leaving $OPENSSH_PKGS in place"
    fi
}

main() {
    parse_args "$@"

    if [ "$(id -u)" != "0" ]; then
        err "this script must run as root (it removes system files)"
    fi

    log "uninstalling the TunnelGate router agent"
    stop_service
    delete_console_key
    delete_console_user
    delete_files
    if [ "$PURGE" = "1" ]; then
        delete_package
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run finished; nothing was changed"
        return 0
    fi

    log "agent removed"
    printf 'The panel still lists this router. Delete it there to release the port and to drop\n'
    printf 'the router key line from the panel authorized_keys.\n'
}

main "$@"
TG_EOF_UNINSTALL
    chmod 0755 "$UNINSTALL_BIN" || err "cannot chmod $UNINSTALL_BIN"
    log "uninstaller written to $UNINSTALL_BIN"
}

# get <path>: value of a field in the exchange response ("" when absent).
get() {
    if [ -r "$JSON_LIB" ]; then
        # shellcheck disable=SC1090  # library path is resolved at install time
        ( . "$JSON_LIB"; json_get "$1" "$RESPONSE_FILE" )
        return $?
    fi
    return 2
}

require_field() {
    _v=$(get "$1")
    [ -n "$_v" ] || err "panel response is missing required field '$1' (stale or foreign panel URL?)"
    printf '%s' "$_v"
}

# cfg_get <option> -> the value of tunnelgate.main.<option>, or nothing.
#
# This lives here because --status needs it and the file had no top-level copy: every other
# cfg_get in this script is inside an embedded heredoc (the Rediscovery of the heartbeat and the
# uninstaller), so it exists on the ROUTER but not in the INSTALLER's own namespace. do_status
# therefore printed "cfg_get: not found" and then silently treated every option as unset - a
# status command that reports a healthy default for a setting it could not read.
#
# uci(1) when it exists; otherwise the same tiny parser the rest of the agent uses, so this works
# on a host where the config was written by the sed fallback.
cfg_get() {
    _tg_value=""
    [ -f "$CONFIG" ] || {
        printf '%s' ""
        return 0
    }
    if command -v uci >/dev/null 2>&1; then
        _tg_value=$(uci -q get "tunnelgate.main.$1" 2>/dev/null)
    else
        _tg_value=$(sed -n "s/^[[:space:]]*option[[:space:]]*$1[[:space:]]*'\(.*\)'[[:space:]]*$/\1/p" \
            "$CONFIG" 2>/dev/null | head -n 1)
    fi
    printf '%s' "$_tg_value"
}

# tls_capability_reason: a short, honest phrase for the log and the refusal text.
#
# Deliberately does NOT say "OpenWrt 21.02 or newer always verifies": only the 19.07 generation
# was measured to accept a self-signed certificate, only the wolfssl libustream variant was
# tested, and early 21.02 point releases had verification problems of their own. The gate is
# "this generation cannot verify (measured)"; the absence of evidence is not proof of safety for
# every newer release, and the wording says which it is.
tls_capability_reason() {
    if [ "${TLS_UNPARSED_RELEASE:-0}" = "1" ]; then
        printf 'this router reports an OpenWrt release we could not parse, so it is treated as one that cannot verify'
        return 0
    fi
    _r=$(detect_openwrt_version)
    printf 'OpenWrt %s is a 19.07-generation release, and such a fetcher was measured to accept a self-signed certificate' "${_r:-?}"
}

# --------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------
# http_post <url> <unused-header-name> <token> <body-file> <output-file> [timeout-seconds]
#
# The header name and the token arguments stay in the signature because the exchange calls them
# positionally, but no request uses them any more: both fetchers send the credential in the JSON
# body only, so it never reaches argv (see the curl branch).
# Prints the HTTP status code; empty when the request never completed.
#
# Two fetchers, and they are NOT interchangeable:
#
#   curl - everything is there: -o/-w for the status, a real Authorization header.
#   wget - on stock OpenWrt this is uclient-fetch. Before 24.10 it has NO --header and no -S,
#          and an unknown option there is not even a hard failure (it prints usage and exits
#          0), so a header on this path is worse than useless - it silently sends nothing and
#          still reports success. uclient-fetch also will not retry a challenged POST with the
#          credentials given to --user, so Basic auth cannot authenticate the exchange.
#          Therefore: no --header at all, the credential rides in the JSON BODY (the panel
#          accepts bootstrap_token / api_token there on every generation), and the status is
#          parsed out of the progress output, all a pre-24.10 uclient-fetch offers.
http_post() {
    _tg_url=$1
    _tg_hname=$2
    _tg_token=$3
    _tg_body=$4
    _tg_out=$5
    _tg_timeout=${6:-60}

    rm -f "$_tg_out" 2>/dev/null
    # Why the last fetch failed, when the fetcher said something useful. It has to go through a
    # FILE: the caller runs this function in a command substitution, i.e. in a subshell, so a
    # variable set here would never reach it.
    rm -f "$HTTP_ERR_FILE" 2>/dev/null

    case "$FETCHER" in
    curl)
        # -k only when the panel explicitly turned verification off (TLS_VERIFY above). It is
        # not folded into -sS, and nothing can switch it on for anything but this request.
        _tg_k=""
        if [ "$TLS_VERIFY" = "0" ]; then
            _tg_k="-k"
        fi
        # -q first: never read ~/.curlrc. 000 is what -w prints when the request never
        # completed (DNS, TLS, refused) - not an HTTP status, so report "no status".
        _tg_errf="$_tg_out.err"
        # NO credential on the command line. -H "X-Bootstrap-Token: ..." and -u "TOKEN:" both put
        # the token in /proc/PID/cmdline, where every local user can read it for as long as the
        # request runs - and the heartbeat does that every 60 s. The JSON body carries it
        # already, and that is the only channel a pre-24.10 uclient-fetch has anyway. Measured
        # against the disposable panel: a body-only POST authenticates the exchange AND the
        # heartbeat, so the header and the basic-auth argument are dropped, not replaced.
        _tg_code=$(curl -q -sS ${_tg_k:+"$_tg_k"} -o "$_tg_out" -w '%{http_code}' --max-time "$_tg_timeout" -X POST \
            -H "Content-Type: application/json" \
            --data-binary "@$_tg_body" \
            "$_tg_url" 2>"$_tg_errf")
        tail -n 1 "$_tg_errf" 2>/dev/null | tr -d '\r' >"$HTTP_ERR_FILE" 2>/dev/null
        rm -f "$_tg_errf"
        case "$_tg_code" in
        000 | "") return 0 ;;
        *)
            printf '%s' "$_tg_code"
            return 0
            ;;
        esac
        ;;
    wget)
        # No -q: the status only exists in the progress output. No --header, no -S (see above).
        # GNU wget (a development host) and uclient-fetch word the same fact differently, so
        # all three spellings are parsed.
        _tg_err="$_tg_out.err"
        _tg_ncc=""
        if [ "$TLS_VERIFY" = "0" ]; then
            _tg_ncc="--no-check-certificate"
        fi
        wget -O "$_tg_out" ${_tg_ncc:+"$_tg_ncc"} --post-file="$_tg_body" --timeout="$_tg_timeout" "$_tg_url" 2>"$_tg_err"
        _tg_rc=$?
        tail -n 1 "$_tg_err" 2>/dev/null | tr -d '\r' >"$HTTP_ERR_FILE" 2>/dev/null
        _tg_code=$(sed -n \
            -e 's/.*HTTP error \([0-9][0-9][0-9]\).*/\1/p' \
            -e 's/.*awaiting response\.\.\. \([0-9][0-9][0-9]\).*/\1/p' \
            -e 's/.*ERROR \([0-9][0-9][0-9]\).*/\1/p' \
            "$_tg_err" 2>/dev/null | tail -n 1)
        rm -f "$_tg_err"
        if [ -n "$_tg_code" ]; then
            printf '%s' "$_tg_code"
            return 0
        fi
        # No status line and a clean exit: answer 200. The caller still validates the body (a
        # missing router_id fails the run), so a captive-portal page cannot slip through.
        [ "$_tg_rc" = "0" ] && printf '200'
        return 0
        ;;
    *) return 1 ;;
    esac
}

# api_error_message <status>: the panel's error envelope, or a plain status when there is no
# body left. On the wget path a 4xx/5xx body is never written, so the fallback is the normal
# case there, not an edge case.
api_error_message() {
    _code=$(get error.code)
    _msg=$(get error.message)
    if [ -n "$_msg" ]; then
        printf '%s (%s)' "$_msg" "${_code:-unknown}"
    else
        printf 'HTTP %s' "$1"
    fi
}

# --------------------------------------------------------------------------------------
# exchange
# --------------------------------------------------------------------------------------
# build_report [token]: the JSON body of the exchange request. The token is a PARAMETER so the
# dry-run path can build a preview with "***" in it without ever putting the real credential in a
# variable that the report then reads. The old save/restore form also tripped the test that greps
# the shipped file for a literal token assignment - a guard worth keeping honest, not relaxing.
build_report() {
    _token=${1-$TG_BOOTSTRAP_TOKEN}
    _hostname=$(detect_hostname)
    _model=$(detect_model)
    _version=$(detect_openwrt_version)
    _mac=$(detect_mac)
    _uptime=$(detect_uptime)

    {
        printf '{"hostname":%s' "$(json_quote "$_hostname")"
        printf ',"model":%s' "$(json_quote "$_model")"
        printf ',"openwrt_version":%s' "$(json_quote "$_version")"
        [ -n "$_mac" ] && printf ',"mac":%s' "$(json_quote "$_mac")"
        printf ',"uptime_seconds":%s' "$_uptime"
        printf ',"client_version":%s' "$(json_quote "$CLIENT_VERSION")"
        # The credential in the body: the only channel a pre-24.10 uclient-fetch can offer.
        printf ',"bootstrap_token":%s' "$(json_quote "$_token")"
        printf '}\n'
    } >"$BODY_FILE" || err "cannot write $BODY_FILE"
}

do_exchange() {
    _url="${TG_PANEL_URL%/}$EXCHANGE_PATH"
    log "exchanging bootstrap token with $_url"

    if [ "$DRY_RUN" = "1" ]; then
        # The real token is never placed in the report on this path: the marker is passed in as
        # an argument, so no file ever holds the credential. A sed-based redaction of a written
        # file was wrong twice over: the file existed with the secret in it, and / is legal in
        # the base64 alphabet, so "s/$TOKEN/***/g" died with "unknown option to s" and printed
        # nothing instead of a redacted preview.
        make_tmp_dir
        build_report "***"
        log "dry-run: would POST this report to $_url:"
        cat "$BODY_FILE"
        return 0
    fi

    # Item of the audit this defends, and what it is worth: on a 19.07-generation router the
    # fetcher accepts a self-signed certificate (measured), so a warning in a log nobody re-reads
    # is not consent. The host key fingerprint arrives in the SAME response that carries the
    # private key, so a MITM can substitute the key, the fingerprint AND the pin together -
    # pin_host_key cannot save this, its input is already attacker-controlled.
    #
    # Refuse BEFORE the POST, when the admin has NOT already accepted the risk in the panel
    # setting. tls_verify=0 is the consent path: the acknowledgement lives in a panel setting
    # with an audit entry, instead of an environment variable on the router (no TG_FORCE bypass
    # here on purpose - TG_FORCE means "skip the OpenWrt check", and mixing two very different
    # risks into one switch is how they both get used by accident).
    #
    # Honest about what the refusal buys: the bootstrap token has already crossed this wire in
    # the download command itself. What it protects is the private key and the api_token handoff.
    if [ "$TLS_UNVERIFIABLE" = "1" ] && [ "$TLS_VERIFY" = "1" ]; then
        err "this router's TLS stack cannot check a certificate ($(tls_capability_reason)), so the panel cannot be authenticated over it. Continuing would send the bootstrap token and the private key across a channel anyone on the path can impersonate (the host key fingerprint arrives in that same response, so it cannot be checked either).
Two ways forward: upgrade the router to OpenWrt 21.02 or newer (where a certificate chain is verified), or - if the panel really does use a self-signed certificate - open Settings > Agent endpoint in the panel and turn the certificate check off for this panel. That is an explicit, audited acknowledgement that the panel cannot be verified from this router.
Nothing has been sent: the bootstrap token already crossed the wire in the download command you pasted, but no private key or API token has."
    fi

    make_tmp_dir
    build_report

    [ "$FETCHER" != "none" ] ||
        err "neither curl nor wget is installed on this router, so the panel cannot be reached; install one of them and re-run"

    _status=$(http_post "$_url" "X-Bootstrap-Token" "$TG_BOOTSTRAP_TOKEN" "$BODY_FILE" "$RESPONSE_FILE")
    if [ -z "$_status" ]; then
        # A TLS-less uclient-fetch and a dead panel fail identically (no status code); the fetcher
        # message is the only thing that tells them apart, and the 19.07 cure is a package that
        # nobody would guess. Name it here rather than in a FAQ.
        _ferr=""
        [ -r "$HTTP_ERR_FILE" ] && _ferr=$(cat "$HTTP_ERR_FILE" 2>/dev/null)
        case "$_ferr" in
        *"SSL support not available"*)
            err "the fetcher on this router has no TLS support, so $_url cannot be reached: install a libustream TLS package (opkg install libustream-wolfssl; on 19.07 the exact name is libustream-wolfssl20150806) and re-run. This is a property of the image, not of the panel"
            ;;
        esac
        if [ -n "$_ferr" ]; then
            err "cannot reach the panel at $_url: $_ferr
DNS, TLS, firewall or a wrong panel URL could each do this. Check 'nslookup', the router clock (https needs a sane date: 'date') and whether tls_verify matches the panel's certificate."
        fi
        err "cannot reach the panel at $_url (DNS, TLS, firewall or a wrong panel URL). Check 'nslookup' and the router clock: https needs a sane date, see 'date'"
    fi
    case "$_status" in
    200 | 201) ;;
    401 | 403 | 404 | 409 | 410)
        err "panel refused the bootstrap token: $(api_error_message "$_status"). Tokens are single-use and short-lived - generate a fresh command in the panel"
        ;;
    5??) err "panel error $_status: $(api_error_message "$_status"); retry in a minute" ;;
    *) err "unexpected panel response HTTP $_status: $(api_error_message "$_status")" ;;
    esac
    [ -s "$RESPONSE_FILE" ] || err "panel returned an empty response body"
    [ -n "$(get router_id)" ] || err "cannot parse the panel response as JSON (no router_id field)"
}

# --------------------------------------------------------------------------------------
# key material - written once, never echoed, never on a command line
# --------------------------------------------------------------------------------------
install_private_key() {
    _key=$(get private_key)
    [ -n "$_key" ] || err "panel response carried no private_key"
    case "$_key" in
    *"PRIVATE KEY"*) ;;
    *) err "private_key in the panel response is not an OpenSSH private key" ;;
    esac

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write the ed25519 private key to $KEY_PATH (mode 0600)"
        return 0
    fi

    _key_dir=$(dirname "$KEY_PATH")
    mkdir -p "$_key_dir" || err "cannot create $_key_dir"
    chmod 0700 "$_key_dir"

    # Re-running the installer is the documented recovery path, so it must not churn the
    # key file: an identical key is left untouched (same bytes, same mtime, no window in
    # which the file is half-written while the tunnel is running).
    if [ -r "$KEY_PATH" ] && [ "$(cat "$KEY_PATH")" = "$_key" ]; then
        chmod 0600 "$KEY_PATH"
        log "private key at $KEY_PATH is already current (0600)"
        return 0
    fi

    ( umask 077; printf '%s\n' "$_key" >"$KEY_PATH" ) || err "cannot write $KEY_PATH"
    chmod 0600 "$KEY_PATH"
    chmod 0700 "$_key_dir"
    # Read the key back with ssh-keygen and require the public half. Do NOT test the exit code:
    # the dropbear build prints "Exited: String too long" for an OpenSSH key and exits 0, so an
    # exit-code check would call a key nothing can use perfectly usable.
    if ! ssh-keygen -y -f "$KEY_PATH" 2>/dev/null | grep -q '^ssh-ed25519 '; then
        err "the private key written to $KEY_PATH is not usable by ssh-keygen: ssh-keygen on PATH is probably the dropbear build (this is what openssh-keygen fixes). Re-run the installer after installing it"
    fi
    log "private key installed at $KEY_PATH (0600)"
}

# --------------------------------------------------------------------------------------
# host key pinning (MITM protection)
# --------------------------------------------------------------------------------------
pin_host_key() {
    _host=$(require_field ssh.host)
    _port=$(require_field ssh.port)
    _want=$(get ssh.host_key_fingerprint)

    if [ -z "$_want" ]; then
        err "panel did not return ssh.host_key_fingerprint; refusing to connect without host key pinning"
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would verify the host key of $_host:$_port against $_want"
        return 0
    fi

    # Real package names: ssh-keyscan ships in openssh-client-utils and OpenSSH ssh-keygen in
    # openssh-keygen; "install openssh-client" alone leaves both of these errors in place.
    command -v ssh-keyscan >/dev/null 2>&1 ||
        err "ssh-keyscan is missing: install openssh-client-utils (ssh-keyscan lives there, not in openssh-client)"
    probe_openssh ssh-keygen ||
        err "ssh-keygen cannot read an OpenSSH private key (it is the dropbear build, or missing): install openssh-keygen and re-run"

    make_tmp_dir
    _scanned="$TMP_DIR/keyscan"
    _pool=""
    _reachable=0
    for _t in ed25519 rsa ecdsa; do
        if ssh-keyscan -T 10 -p "$_port" -t "$_t" "$_host" >"$_scanned" 2>/dev/null &&
            [ -s "$_scanned" ]; then
            # The host answered at least once, so an empty _pool at the end means a real key
            # mismatch rather than an unreachable host. That distinction saves an operator an
            # hour of hunting a MITM that is actually a firewall.
            _reachable=1
            # Pin the ONE key we were told about, not every key of that type the host publishes.
            # A host with two ed25519 keys would otherwise get both pinned, and the second would
            # keep being accepted even after the first was revoked.
            #
            # Each candidate line is fingerprinted IN ISOLATION (ssh-keygen -lf - reads a single
            # key from stdin) instead of fingerprinting the whole file and hoping the output order
            # matches the line order, which it only does for a well-formed file. The comparison is
            # on the whole fingerprint FIELD: a substring match (grep -F on the full output) would
            # accept a fingerprint that merely contains the wanted one.
            #
            # ssh-keyscan prefixes each block with a "# host:port SSH-2.0-..." comment: it carries
            # no key and would accumulate one copy per run, so it is skipped here and never pinned.
            _pool=$(
                while IFS= read -r _cand; do
                    case "$_cand" in
                    "" | "#"*) continue ;;
                    esac
                    _cfp=$(printf '%s\n' "$_cand" | ssh-keygen -lf - 2>/dev/null | awk 'NR == 1 { print $2 }')
                    if [ "$_cfp" = "$_want" ]; then
                        printf '%s\n' "$_cand"
                    fi
                done <"$_scanned"
            )
            if [ -n "$_pool" ]; then
                break
            fi
        fi
    done
    rm -f "$_scanned"

    if [ -z "$_pool" ]; then
        # Two very different situations that used to print the same sentence. A firewall gives
        # exactly the same empty answer as a MITM, and an operator sent hunting a MITM that is a
        # blocked port wastes an hour.
        if [ "$_reachable" = "1" ]; then
            err "HOST KEY MISMATCH for $_host:$_port: the host answered, but no key it offered has fingerprint $_want. Refusing to continue (possible MITM, or a stale ssh host key fingerprint on the panel - re-scan it in the panel and retry)"
        fi
        err "could not fetch the host keys of $_host:$_port: ssh-keyscan got no answer at all. This is a firewall, a wrong ssh port or a DNS problem on the router, NOT a key mismatch. Fix the path to the panel's ssh port and re-run"
    fi

    _kh_dir=$(dirname "$KNOWN_HOSTS")
    mkdir -p "$_kh_dir" || err "cannot create $_kh_dir"
    chmod 0700 "$_kh_dir"
    [ -f "$KNOWN_HOSTS" ] || : >"$KNOWN_HOSTS"
    chmod 0600 "$KNOWN_HOSTS"

    # Replace only the entries for this host; other panels' pins stay.
    _hostpat="$_host"
    [ "$_port" = "22" ] || _hostpat="[$_host]:$_port"
    _tmp="$KNOWN_HOSTS.tg-new.$$"
    grep -vF "$_hostpat " "$KNOWN_HOSTS" >"$_tmp" 2>/dev/null || : >"$_tmp"
    printf '%s\n' "$_pool" >>"$_tmp"
    chmod 0600 "$_tmp"
    mv "$_tmp" "$KNOWN_HOSTS" || err "cannot update $KNOWN_HOSTS"
    log "host key of $_host:$_port pinned in $KNOWN_HOSTS ($_want)"
}

# --------------------------------------------------------------------------------------
# console: the panel authenticates INTO the router's dropbear
# --------------------------------------------------------------------------------------
console_is_enabled() {
    case "$(get console.enabled)" in
    true | 1) return 0 ;;
    *) return 1 ;;
    esac
}

# The console account actually in use, and the authorized_keys file that account's dropbear
# really reads. Both are decided HERE and written to UCI by write_config, so the panel and the
# router can never disagree about which account to log in as.
#
# Why this exists: a non-root account created with 'adduser -D -H' has no home directory, and
# /etc/dropbear/authorized_keys belongs to root - dropbear only consults it for root. Writing the
# console key there while UCI names a non-root user produced a console that never opened, with
# nothing in any log explaining it.
CONSOLE_USER_EFFECTIVE=root
CONSOLE_KEYS_EFFECTIVE=""
# 1 when this run created the account, 0 when it already existed. Written to UCI and used by BOTH
# uninstallers: deleting an account the installer did not create would destroy somebody's login,
# and leaving a created one behind after --purge leaves a password-less shell account forever.
CONSOLE_USER_CREATED=0

ensure_console_user() {
    _user=$(get console.ssh_user)
    _shell=$(get console.shell)
    [ -n "$_shell" ] || _shell=/bin/ash
    [ -n "$_user" ] || _user=root

    CONSOLE_USER_EFFECTIVE=$_user
    CONSOLE_KEYS_EFFECTIVE=$(get console.authorized_keys_path)
    [ -n "$CONSOLE_KEYS_EFFECTIVE" ] || CONSOLE_KEYS_EFFECTIVE=/etc/dropbear/authorized_keys

    if [ "$_user" = "root" ]; then
        log "console user: root (see docs/SECURITY.md for the trade-off and the UCI switch)"
        return 0
    fi

    if ! id -u "$_user" >/dev/null 2>&1; then
        # A dedicated, password-less, shell-only account. Deliberately NOT added to any group:
        # granting uci/ubus rights needs a sudo/polkit policy that differs per firmware, and a
        # half-applied group membership is worse than the documented root fallback. A HOME is
        # required now (-H drops it) because the per-user authorized_keys lives in it.
        if run_cmd adduser -D -s "$_shell" -G nogroup "$_user" 2>/dev/null ||
            run_cmd adduser -D -s "$_shell" "$_user" 2>/dev/null; then
            CONSOLE_USER_CREATED=1
            log "console user $_user created with shell $_shell"
        else
            # NEVER leave the config naming an account that does not exist: the panel would keep
            # trying a login that cannot succeed and the operator would see a console that never
            # opens, with no error anywhere. Fall back to root in the config, loudly.
            CONSOLE_USER_EFFECTIVE=root
            CONSOLE_KEYS_EFFECTIVE=$(get console.authorized_keys_path)
            [ -n "$CONSOLE_KEYS_EFFECTIVE" ] || CONSOLE_KEYS_EFFECTIVE=/etc/dropbear/authorized_keys
            log "WARNING: could not create console user $_user on this firmware. The console will connect as root, and 'console_user' in $CONFIG is set to root so the panel asks for an account that exists. Create the account by hand and re-run the installer to use it"
            return 0
        fi
    else
        log "console user $_user already exists"
    fi

    # dropbear reads /etc/dropbear/authorized_keys for root only; any other account needs its own
    # ~/.ssh/authorized_keys. Point UCI (and the heartbeat) at the file this account reads.
    _home=$(awk -F: -v u="$_user" '$1 == u { print $6 }' "$PASSWD_FILE" 2>/dev/null | head -n 1)
    case "$_home" in
    "" | /)
        # No usable home: the per-user key cannot be placed, so refuse the non-root console
        # instead of installing a key nobody will ever be asked for.
        CONSOLE_USER_EFFECTIVE=root
        CONSOLE_KEYS_EFFECTIVE=$(get console.authorized_keys_path)
        [ -n "$CONSOLE_KEYS_EFFECTIVE" ] || CONSOLE_KEYS_EFFECTIVE=/etc/dropbear/authorized_keys
        log "WARNING: console user $_user has no home directory, and dropbear only reads /etc/dropbear/authorized_keys for root. Falling back to a root console, and 'console_user' in $CONFIG is set to root"
        return 0
        ;;
    esac
    CONSOLE_KEYS_EFFECTIVE="$_home/.ssh/authorized_keys"
    log "console user: $_user, key file $CONSOLE_KEYS_EFFECTIVE (dropbear reads the root file only for root)"
}

prepare_console() {
    console_is_enabled || {
        log "console disabled by the panel for this router"
        return 0
    }

    # The EFFECTIVE path, chosen by ensure_console_user: for a non-root console account that is
    # that account's own ~/.ssh/authorized_keys, because dropbear only reads the root file as root.
    _keys_path=$CONSOLE_KEYS_EFFECTIVE
    [ -n "$_keys_path" ] || _keys_path=/etc/dropbear/authorized_keys
    _dir=$(dirname "$_keys_path")

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would prepare $_dir (0700) / $_keys_path (0600) and enable dropbear"
        return 0
    fi

    mkdir -p "$_dir" || err "cannot create $_dir"
    chmod 0700 "$_dir"
    [ -f "$_keys_path" ] || : >"$_keys_path"
    chmod 0600 "$_keys_path"

    if [ -x /etc/init.d/dropbear ]; then
        /etc/init.d/dropbear enable >/dev/null 2>&1 && log "dropbear enabled"
        /etc/init.d/dropbear running >/dev/null 2>&1 ||
            /etc/init.d/dropbear start >/dev/null 2>&1
    else
        log "warning: /etc/init.d/dropbear not found; the console needs dropbear running"
    fi

    # The panel creates its console key lazily, so the public half arrives via heartbeat.
    log "console key will be installed by the heartbeat once the panel creates it"
}
# --------------------------------------------------------------------------------------
# configuration and service files
# --------------------------------------------------------------------------------------
# uci_quote_raw: values we write into UCI are single-quoted. A single quote cannot be
# escaped inside a UCI single-quoted string without ambiguity, and none of the values (URL,
# slug, base64 token, port, host, path) can legitimately contain one - so strip instead of
# producing a config UCI cannot parse.
uci_quote_raw() {
    printf '%s' "$1" | sed "s/'//g"
}

write_config() {
    _panel_url=${TG_PANEL_URL%/}
    _router_id=$(require_field router_id)
    _api_token=$(require_field api_token)
    _heartbeat_url=$(require_field heartbeat_url)
    _ssh_host=$(require_field ssh.host)
    _ssh_port=$(require_field ssh.port)
    _ssh_user=$(require_field ssh.username)
    _remote_port=$(require_field tunnel.remote_port)
    _bind=$(get tunnel.bind_address)
    [ -n "$_bind" ] || _bind=127.0.0.1
    _local_port=$(get tunnel.router_http_port)
    [ -n "$_local_port" ] || _local_port=80
    _console_enabled=0
    console_is_enabled && _console_enabled=1
    _console_port=$(get console.console_port)
    _console_target=$(get console.target_port)
    [ -n "$_console_target" ] || _console_target=22
    _console_keys=$CONSOLE_KEYS_EFFECTIVE
    [ -n "$_console_keys" ] || _console_keys=/etc/dropbear/authorized_keys
    # The EFFECTIVE account, not the requested one: ensure_console_user falls back to root when
    # the requested account cannot be created or has no home for a per-user key. Writing the
    # requested name here regardless was the bug that produced a console nobody could open.
    _console_user=$CONSOLE_USER_EFFECTIVE
    [ -n "$_console_user" ] || _console_user=root
    # Persisted so the heartbeat keeps the same policy once this installer exits, and so the
    # operator can flip it later with 'uci set tunnelgate.main.tls_verify=0' + a restart.
    _tls_verify=$TLS_VERIFY

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write $CONFIG (panel $_ssh_host:$_ssh_port, tunnel port $_remote_port, console enabled=$_console_enabled)"
        return 0
    fi

    # Whole-file write on purpose: re-running the installer must REPLACE the main section,
    # not append a second one (UCI would then keep both and 'uci -q get' would be ambiguous).
    mkdir -p "$(dirname "$CONFIG")" || err "cannot create $(dirname "$CONFIG")"
    cat >"$CONFIG" <<EOF_UCI || err "cannot write $CONFIG"
config tunnelgate 'main'
	option panel_url '$(uci_quote_raw "$_panel_url")'
	option router_id '$(uci_quote_raw "$_router_id")'
	option api_token '$(uci_quote_raw "$_api_token")'
	option client_version '$(uci_quote_raw "$CLIENT_VERSION")'
	option ssh_host '$(uci_quote_raw "$_ssh_host")'
	option ssh_port '$(uci_quote_raw "$_ssh_port")'
	option ssh_user '$(uci_quote_raw "$_ssh_user")'
	option key_path '$(uci_quote_raw "$KEY_PATH")'
	option known_hosts_path '$(uci_quote_raw "$KNOWN_HOSTS")'
	option json_lib '$(uci_quote_raw "$JSON_LIB")'
	option bind_address '$(uci_quote_raw "$_bind")'
	option tunnel_port '$(uci_quote_raw "$_remote_port")'
	option local_port '$(uci_quote_raw "$_local_port")'
	option heartbeat_enabled '1'
	option heartbeat_url '$(uci_quote_raw "$_heartbeat_url")'
	option console_enabled '$_console_enabled'
	option console_port '$(uci_quote_raw "$_console_port")'
	option console_target_port '$(uci_quote_raw "$_console_target")'
	option console_user '$(uci_quote_raw "$_console_user")'
	option console_authorized_keys_path '$(uci_quote_raw "$_console_keys")'
	option console_user_created '$CONSOLE_USER_CREATED'
	option console_serial '0'
	option tls_verify '$_tls_verify'
EOF_UCI
    chmod 0600 "$CONFIG"
    log "configuration written to $CONFIG (0600: it holds the API token)"
}

write_init_script() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write $INITD and enable it"
        return 0
    fi
    mkdir -p "$(dirname "$INITD")" || err "cannot create $(dirname "$INITD")"
    cat >"$INITD" <<'TG_EOF_INIT' || err "cannot write $INITD (out of space?)"
#!/bin/sh /etc/rc.common
# shellcheck shell=sh disable=SC2034,SC1091,SC2317
# TunnelGate agent - procd service (installed as /etc/init.d/tunnelgate).
#
# Two procd instances, one init script:
#   * "tunnelgate"            - the ssh reconnect loop (/usr/bin/ssh-loop)
#   * "tunnelgate-heartbeat"  - sends a heartbeat every 60 s (/usr/bin/tunnelgate-heartbeat)
#
# Both are respawned by procd, so a crash is recovered without any external supervisor. The
# loop itself also reconnects internally; procd is the backstop for when the loop exists
# wrong (a broken script edit, an OOM kill).
#
# Why not autossh: one less package to install and to survive a firmware upgrade, and procd
# already provides process supervision with a respawn policy.

START=95
STOP=10
USE_PROCD=1

PROG=${TG_LOOP_BIN:-/usr/bin/ssh-loop}
HEARTBEAT_PROG=${TG_HB_BIN:-/usr/bin/tunnelgate-heartbeat}

is_enabled() {
    _value=""
    if command -v uci >/dev/null 2>&1; then
        _value=$(uci -q get "tunnelgate.main.$1" 2>/dev/null)
    fi
    [ "$_value" = "1" ]
}

start_service() {
    procd_open_instance tunnelgate
    procd_set_param command "$PROG"
    # respawn <threshold> <timeout> <retry>: keep restarting forever (0 = unlimited), with a
    # 5 s spacing so a hard-failing ssh cannot spin the CPU.
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 0
    # stderr 1 -> ssh(1) diagnostics land in logread as "tunnelgate: ..." entries. The loop
    # already forwards them itself; procd_set_param stderr 1 keeps a hard crash visible too.
    procd_set_param stderr 1
    procd_set_param limits nofile="1024 1024"
    procd_set_param pidfile /var/run/tunnelgate.pid
    procd_close_instance

    # The heartbeat is a separate instance so a hung HTTP POST never delays the tunnel, and
    # so an operator can disable it with 'option heartbeat_enabled 0' without touching ssh.
    if is_enabled heartbeat_enabled; then
        procd_open_instance heartbeat
        procd_set_param command /bin/sh -c "while :; do \"$HEARTBEAT_PROG\"; sleep 60; done"
        procd_set_param respawn 3600 60 0
        procd_set_param stdout 0
        procd_set_param stderr 1
        procd_close_instance
    fi
}

reload_service() {
    stop
    start
}

service_triggers() {
    procd_add_reload_trigger "tunnelgate"
}
TG_EOF_INIT
    chmod 0755 "$INITD"
    log "init script written to $INITD"
}

# --------------------------------------------------------------------------------------
# service control
# --------------------------------------------------------------------------------------
service_start() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would enable and start $INITD"
        return 0
    fi
    if [ "$SKIP_SERVICE" = "1" ]; then
        log "TG_SKIP_SERVICE=1: staged the files but did not touch the init system"
        return 0
    fi
    "$INITD" enable || err "cannot enable $INITD"
    "$INITD" restart || err "cannot start $INITD"
    log "service enabled and started"
}

service_stop() {
    [ -x "$INITD" ] || return 0
    [ "$SKIP_SERVICE" = "1" ] && return 0
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would stop and disable $INITD"
        return 0
    fi
    "$INITD" stop >/dev/null 2>&1
    "$INITD" disable >/dev/null 2>&1
}

print_summary() {
    _host=$(get ssh.host)
    _port=$(get ssh.port)
    _remote=$(get tunnel.remote_port)
    _local=$(get tunnel.router_http_port)
    _url=$(get tunnel.url)
    if console_is_enabled; then
        _console=$(get console.console_port)
    else
        _console="disabled"
    fi

    printf '\n'
    printf '  TunnelGate router agent installed.\n'
    printf '\n'
    printf '    panel           %s\n' "$TG_PANEL_URL"
    printf '    ssh endpoint    %s:%s\n' "${_host:-?}" "${_port:-?}"
    printf '    reverse tunnel  127.0.0.1:%s -> 127.0.0.1:%s\n' "${_remote:-?}" "${_local:-?}"
    printf '    console         %s\n' "$_console"
    printf '    luci url        %s\n' "${_url:-see the panel}"
    printf '    config          %s (mode 0600, contains the API token)\n' "$CONFIG"
    printf '    private key     %s (mode 0600, never leaves this router)\n' "$KEY_PATH"
    printf '\n'
    printf '  Verify:  /etc/init.d/tunnelgate status ; logread -e tunnelgate | tail -20\n'
    printf '  Remove:  %s [--purge]  (or re-run: sh install.sh --uninstall)\n' "$UNINSTALL_BIN"
    printf '\n'
    log "installer finished"
}

do_status() {
    printf 'mode            : %s\n' "$MODE"
    if [ -x "$INITD" ]; then
        printf 'init script     : %s (present)\n' "$INITD"
    else
        printf 'init script     : missing\n'
    fi
    if [ -f "$CONFIG" ]; then
        printf 'config          : %s\n' "$CONFIG"
        if command -v uci >/dev/null 2>&1; then
            for _k in panel_url ssh_host ssh_port tunnel_port local_port console_enabled console_port router_id tls_verify; do
                printf '  %-15s %s\n' "$_k" "$(uci -q get "tunnelgate.main.$_k" 2>/dev/null)"
            done
        fi
        case "$(config_tls_verify)" in
        0) printf '  %-15s %s\n' 'tls policy' 'OFF - the panel certificate is NOT verified' ;;
        *) printf '  %-15s %s\n' 'tls policy' 'verify (default)' ;;
        esac
        # The policy is one thing, whether this router CAN honour it is another, and only saying
        # "verify" while the fetcher accepts any certificate would be a lie in the one command an
        # operator runs to find out what is going on.
        detect_fetcher
        case "$(cfg_get panel_url)" in
        https://*)
            if tls_stack_cannot_verify; then
                printf '  %-15s %s\n' 'tls capability' \
                    "CANNOT verify on this release - tls_verify=1 is not being enforced here"
            else
                printf '  %-15s %s\n' 'tls capability' 'checks the certificate chain'
            fi
            ;;
        *) printf '  %-15s %s\n' 'tls capability' 'plain http - there is no certificate at all' ;;
        esac
    else
        printf 'config          : missing (not installed)\n'
    fi
    if [ -r "$KEY_PATH" ]; then
        printf 'private key     : %s (present)\n' "$KEY_PATH"
    else
        printf 'private key     : missing\n'
    fi
    [ -x "$INITD" ] && "$INITD" status 2>&1
    return 0
}

do_uninstall() {
    log "uninstalling the TunnelGate agent"
    service_stop

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would remove $INITD, $CONFIG, $LOOP_BIN, $HB_BIN,"
        log "dry-run: would remove $UNINSTALL_BIN, $STATE_DIR, $KEY_PATH and the console key line"
        return 0
    fi

    # Console key line: remove only ours, keep whatever else the operator has in that file.
    _keys_path=${TG_KEYS:-/etc/dropbear/authorized_keys}
    if [ -f "$CONFIG" ] && command -v uci >/dev/null 2>&1; then
        _cfg_keys=$(uci -q get tunnelgate.main.console_authorized_keys_path 2>/dev/null)
        [ -n "$_cfg_keys" ] && _keys_path="$_cfg_keys"
    fi
    if [ -f "$_keys_path" ] && grep -q " tunnelgate-console\$" "$_keys_path" 2>/dev/null; then
        _tmp="$_keys_path.tg-new.$$"
        grep -v " tunnelgate-console\$" "$_keys_path" >"$_tmp" 2>/dev/null
        if chmod 0600 "$_tmp" && mv "$_tmp" "$_keys_path"; then
            log "removed the tunnelgate-console line from $_keys_path"
        fi
    fi

    if [ "$PURGE" = "1" ]; then
        _console_user=""
        _console_created=0
        if [ -f "$CONFIG" ] && command -v uci >/dev/null 2>&1; then
            _console_user=$(uci -q get tunnelgate.main.console_user 2>/dev/null)
            _console_created=$(uci -q get tunnelgate.main.console_user_created 2>/dev/null)
        fi
        # Only an account this installer created is removed. A pre-existing account somebody else
        # made would be somebody's login, and --purge must not delete it.
        if [ "$_console_created" != "1" ] && [ -n "$_console_user" ]; then
            log "keeping console user $_console_user: the installer did not create it"
            _console_user=""
        fi
        case "$_console_user" in
        "" | root) ;;
        *)
            if id -u "$_console_user" >/dev/null 2>&1; then
                log "removing console user $_console_user"
                deluser "$_console_user" >/dev/null 2>&1 ||
                    log "warning: could not remove console user $_console_user"
            fi
            ;;
        esac
    fi

    rm -f "$INITD" "$CONFIG" "$LOOP_BIN" "$HB_BIN" "$UNINSTALL_BIN"
    rm -rf "$STATE_DIR"
    rm -f "$KEY_PATH"
    rm -f /tmp/tunnelgate-exchange.* /tmp/tunnelgate-report.* /tmp/tunnelgate-heartbeat-* 2>/dev/null

    if [ "$PURGE" = "1" ]; then
        # The SAME three packages agent/uninstall.sh removes, and for the same reason: the
        # installer adds openssh-client, openssh-keygen and openssh-client-utils, and leaving the
        # last one behind on 24.10 keeps an ssh-keygen that shadows dropbear's.
        case "$(detect_pkg_manager)" in
        apk)
            for _pkg in $OPENSSH_PKGS; do
                log "removing $_pkg via apk"
                apk del "$_pkg" >/dev/null 2>&1 || log "warning: apk could not remove $_pkg"
            done
            ;;
        opkg)
            for _pkg in $OPENSSH_PKGS; do
                log "removing $_pkg via opkg"
                opkg remove "$_pkg" >/dev/null 2>&1 || log "warning: opkg could not remove $_pkg"
            done
            ;;
        esac
    fi

    log "agent removed"
    printf 'The panel still lists this router: delete it there to release the port and the\n'
    printf 'authorized_keys line on the panel host.\n'
}

# --------------------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------------------
main() {
    parse_args "$@"

    case "$MODE" in
    status)
        check_root
        do_status
        exit 0
        ;;
    restart)
        check_root
        [ -x "$INITD" ] || err "not installed ($INITD missing)"
        "$INITD" restart || err "restart failed"
        log "service restarted"
        exit 0
        ;;
    uninstall)
        check_root
        do_uninstall
        exit 0
        ;;
    esac

    check_root
    check_self
    check_openwrt
    check_placeholders
    detect_fetcher
    resolve_tls_verify
    if [ "$TLS_VERIFY" = "0" ]; then
        log "WARNING: TLS certificate verification is OFF for ${TG_PANEL_URL:-the panel} (tls_verify=0). Anyone who can answer for that host receives the bootstrap token and the API token. Turn it back on with: uci set tunnelgate.main.tls_verify=1"
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would check/install the OpenSSH client"
        log "dry-run: would check/install a libustream TLS package when https needs one"
    else
        ensure_openssh
        # After the OpenSSH work and before the exchange: on 19.07 the exchange itself is the
        # first https request this router makes, and it fails with a message about uclient-fetch.
        ensure_tls_lib
        # Decide ONCE whether this router could actually verify a certificate chain. Only https
        # presents a certificate at all, so http never counts as "unverifiable".
        TLS_UNVERIFIABLE=0
        case "$TG_PANEL_URL" in
        https://*)
            if tls_stack_cannot_verify; then
                TLS_UNVERIFIABLE=1
            fi
            ;;
        esac
        if [ "$TLS_UNVERIFIABLE" = "1" ] && [ "$TLS_VERIFY" = "0" ]; then
            # The consent path: the admin already turned verification off in the panel, so the
            # acknowledgement exists where an audit log can see it. Warn once, then go on.
            log "WARNING: this router's TLS stack cannot check a certificate chain ($(tls_capability_reason)), and tls_verify=0, so the panel is unauthenticated. The panel setting is the recorded acknowledgement; anyone who can answer for that host receives the bootstrap token and the API token"
        fi
    fi

    write_json_lib
    write_loop_bin
    write_heartbeat_bin
    write_uninstall_bin

    do_exchange

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would install the private key, pin the host key, prepare the console,"
        log "dry-run: write $CONFIG and $INITD, then enable and start the service"
        exit 0
    fi

    install_private_key
    pin_host_key
    ensure_console_user
    prepare_console
    write_config
    write_init_script
    service_start
    print_summary
}

main "$@"
