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
# TG_SKIP_SERVICE=1 stages the files but does not call the init script (test suite only).
SKIP_SERVICE="${TG_SKIP_SERVICE:-0}"
DEF_RESPONSE="/tmp/tunnelgate-exchange.$$"
DEF_BODY="/tmp/tunnelgate-report.$$"
# Where http_post leaves the fetcher's complaint (it runs in a command substitution, so it
# cannot return a variable); do_exchange turns that line into an actionable error.
HTTP_ERR_FILE="/tmp/tunnelgate-fetch-err.$$"

MODE="install"
DRY_RUN=0
PURGE=0
RESPONSE_FILE="$DEF_RESPONSE"
BODY_FILE="$DEF_BODY"

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
    rm -f "$DEF_RESPONSE" "$DEF_BODY" "$HTTP_ERR_FILE"
    rm -rf "${TMPDIR:-/tmp}/tg-probe.$$" 2>/dev/null
}

trap cleanup EXIT INT TERM

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
    [ -r /etc/openwrt_release ] ||
        err "this does not look like OpenWrt (/etc/openwrt_release is missing); set TG_FORCE=1 only for testing"
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
    if [ -r /lib/libustream-ssl.so ] || [ -r /usr/lib/libustream-ssl.so ]; then
        return 1 # a TLS-capable libustream is already there; any variant is enough
    fi
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

# 0 when this image's uclient-fetch CANNOT validate a certificate chain, whatever tls_verify
# says. MEASURED, not assumed: on 19.07.10 with libustream-wolfssl20150806 + ca-bundle installed,
# uclient-fetch ACCEPTS a self-signed certificate (it fetched our self-signed test panel and
# answered 401, where 21.02.7, 22.03.7, 23.05.5 and 24.10.1 all answer "Connection error: Invalid
# SSL certificate"), while a hostname mismatch IS still caught. So on that generation
# tls_verify=1 does not mean "the chain was checked", and saying it does would be a lie. 19.07 is
# below the supported floor (21.02) but people run it, so say what is true rather than refuse.
tls_stack_cannot_verify() {
    case "$FETCHER" in
    wget) ;;
    *) return 1 ;; # curl links its own SSL and does validate
    esac
    _rel=$(detect_openwrt_version)
    [ -n "$_rel" ] || return 1
    _major=${_rel%%.*}
    case "$_major" in
    [0-9]*) ;;
    *) return 1 ;;
    esac
    [ "$_major" -lt 21 ] 2>/dev/null
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
    if [ -r /etc/openwrt_release ]; then
        sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" /etc/openwrt_release | head -n 1 | cut -c1-64
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
    cat >"$JSON_LIB" <<'TG_EOF_JSON'
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
    cat >"$LOOP_BIN" <<'TG_EOF_LOOP'
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
    stderr_file="/tmp/tunnelgate-ssh-$$.log"
    : >"$stderr_file"

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

    "$@" 2>"$stderr_file"
    rc=$?

    # ssh(1) diagnostics (host key mismatch, "remote port forwarding failed", DNS errors) are
    # the only useful text and contain no key material - forward them to syslog ourselves,
    # because the procd instance runs with stderr 0 to keep the log format uniform.
    if [ -s "$stderr_file" ]; then
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
    cat >"$HB_BIN" <<'TG_EOF_HB'
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
# The JSON reader is installed next to the other agent files; the installer writes
# its exact path into UCI (TG_LIB_DIR overrides it, for tests and odd layouts).
LIB_DIR=${TG_LIB_DIR:-}
CLIENT_VERSION="1.0"
DEFAULT_KEYS=${TG_KEYS:-/etc/dropbear/authorized_keys}
TMP_BODY=/tmp/tunnelgate-heartbeat-body.$$
RESPONSE=/tmp/tunnelgate-heartbeat-response.$$
CONSOLE_MARK=tunnelgate-console

# The fetcher is probed once, for the same reason as in install.sh: stock OpenWrt has no curl,
# and its uclient-fetch has no --header before 24.10.
FETCHER=""
if command -v curl >/dev/null 2>&1; then
    FETCHER=curl
elif command -v wget >/dev/null 2>&1; then
    FETCHER=wget
fi

umask 077
trap 'rm -f "$TMP_BODY" "$RESPONSE"' EXIT INT TERM


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

cfg_set() {
    if command -v uci >/dev/null 2>&1; then
        uci -q set "tunnelgate.main.$1=$2" && uci -q commit tunnelgate
        return $?
    fi
    # Fallback for a host without uci (test suite, or a stripped image): rewrite the option
    # in place so the serial really is persisted and the next heartbeat does not reinstall
    # the same console key forever.
    [ -r "$CONFIG_FILE" ] || return 1
    _tmp="$CONFIG_FILE.tg-new.$$"
    if grep -q "^[[:space:]]*option[[:space:]]*$1[[:space:]]" "$CONFIG_FILE" 2>/dev/null; then
        sed "s|^[[:space:]]*option[[:space:]]*$1[[:space:]].*|\toption $1 '$2'|"             "$CONFIG_FILE" >"$_tmp" 2>/dev/null || { rm -f "$_tmp"; return 1; }
    else
        { cat "$CONFIG_FILE"; printf "\toption %s '%s'\n" "$1" "$2"; } >"$_tmp" 2>/dev/null ||
            { rm -f "$_tmp"; return 1; }
    fi
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
        _tg_code=$(curl -q -sS ${_tg_k:+"$_tg_k"} -o "$_tg_out" -w '%{http_code}' --max-time 30 -X POST \
            -H "Content-Type: application/json" \
            -H "X-Api-Token: $_tg_token" \
            -u "$_tg_token:" \
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
    if [ -r /etc/openwrt_release ]; then
        _openwrt=$(sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" /etc/openwrt_release | head -n 1)
    fi
    _uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)
    [ -n "$_uptime" ] || _uptime=0
    _tunnel_pid=$(cfg_get tunnel_pid)

    {
        printf '{"hostname":%s' "$(json_quote "$_hostname")"
        printf ',"model":%s' "$(json_quote "$_model")"
        printf ',"openwrt_version":%s' "$(json_quote "$_openwrt")"
        printf ',"uptime_seconds":%s' "$_uptime"
        printf ',"client_version":%s' "$(json_quote "$CLIENT_VERSION")"
        [ -n "$_tunnel_pid" ] && printf ',"tunnel_pid":%s' "$_tunnel_pid"
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
    _tls_warned=${TG_TLS_WARN_FILE:-/tmp/.tunnelgate-tls-warning}
    if [ ! -e "$_tls_warned" ]; then
        log "WARNING: TLS certificate verification is OFF for $heartbeat_url (tunnelgate.main.tls_verify=0). Anyone who can answer for that host receives the API token. Restore it with: uci set tunnelgate.main.tls_verify=1 && uci commit tunnelgate && /etc/init.d/tunnelgate restart"
        : >"$_tls_warned" 2>/dev/null
    fi
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
reg_keys_path=$(json_get console.authorized_keys_path "$RESPONSE")
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

write_uninstall_bin() {
    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would write $UNINSTALL_BIN (uninstaller)"
        return 0
    fi
    mkdir -p "$(dirname "$UNINSTALL_BIN")" || err "cannot create $(dirname "$UNINSTALL_BIN")"
    cat >"$UNINSTALL_BIN" <<'TG_EOF_UNINSTALL'
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
    case "$_user" in
    "" | root) return 0 ;;
    esac
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
    chmod 0755 "$HB_BIN"
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

# --------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------
# http_post <url> <header-name> <token> <body-file> <output-file> [timeout-seconds]
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
        _tg_errf="$_tg_out.err.$$"
        _tg_code=$(curl -q -sS ${_tg_k:+"$_tg_k"} -o "$_tg_out" -w '%{http_code}' --max-time "$_tg_timeout" -X POST \
            -H "Content-Type: application/json" \
            -H "$_tg_hname: $_tg_token" \
            -u "$_tg_token:" \
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
        _tg_err="$_tg_out.err.$$"
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
build_report() {
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
        printf ',"bootstrap_token":%s' "$(json_quote "$TG_BOOTSTRAP_TOKEN")"
        printf '}\n'
    } >"$BODY_FILE" || err "cannot write $BODY_FILE"
}

do_exchange() {
    build_report
    _url="${TG_PANEL_URL%/}$EXCHANGE_PATH"
    log "exchanging bootstrap token with $_url"

    if [ "$DRY_RUN" = "1" ]; then
        log "dry-run: would POST this report to $_url:"
        # The report carries the token now, and dry-run output goes to a terminal and to
        # whatever captures it - print the shape, never the credential.
        sed "s/$TG_BOOTSTRAP_TOKEN/***/g" "$BODY_FILE"
        return 0
    fi

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

    _scanned=/tmp/tunnelgate-keyscan.$$
    _pool=""
    for _t in ed25519 rsa ecdsa; do
        if ssh-keyscan -T 10 -p "$_port" -t "$_t" "$_host" >"$_scanned" 2>/dev/null &&
            [ -s "$_scanned" ] &&
            ssh-keygen -lf "$_scanned" 2>/dev/null | grep -qF "$_want"; then
            # ssh-keyscan prefixes each block with a "# host:port SSH-2.0-..." comment.
            # It carries no key, would never be matched by the host pattern below and
            # would therefore accumulate one copy per run - drop it here.
            _pool=$(grep -v '^#' "$_scanned")
            break
        fi
    done
    rm -f "$_scanned"

    if [ -z "$_pool" ]; then
        err "HOST KEY MISMATCH for $_host:$_port: no key from ssh-keyscan matches $_want. Refusing to continue (possible MITM, or a stale ssh host key fingerprint on the panel)"
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

ensure_console_user() {
    _user=$(get console.ssh_user)
    _shell=$(get console.shell)
    [ -n "$_shell" ] || _shell=/bin/ash
    [ -n "$_user" ] || _user=root

    if [ "$_user" = "root" ]; then
        log "console user: root (see docs/SECURITY.md for the trade-off and the UCI switch)"
        return 0
    fi
    if id -u "$_user" >/dev/null 2>&1; then
        log "console user $_user already exists"
        return 0
    fi

    # A dedicated, password-less, shell-only account. Deliberately NOT added to any group:
    # granting uci/ubus rights needs a sudo/polkit policy that differs per firmware, and a
    # half-applied group membership is worse than the documented root fallback.
    if run_cmd adduser -D -H -s "$_shell" -G nogroup "$_user" 2>/dev/null ||
        run_cmd adduser -D -s "$_shell" "$_user" 2>/dev/null; then
        log "console user $_user created with shell $_shell"
        return 0
    fi
    log "warning: could not create console user $_user; the console will connect as root"
}

prepare_console() {
    console_is_enabled || {
        log "console disabled by the panel for this router"
        return 0
    }

    _keys_path=$(get console.authorized_keys_path)
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
    _console_keys=$(get console.authorized_keys_path)
    [ -n "$_console_keys" ] || _console_keys=/etc/dropbear/authorized_keys
    _console_user=$(get console.ssh_user)
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
    cat >"$INITD" <<'TG_EOF_INIT'
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
        if [ -f "$CONFIG" ] && command -v uci >/dev/null 2>&1; then
            _console_user=$(uci -q get tunnelgate.main.console_user 2>/dev/null)
        fi
        case "$_console_user" in
        "" | root) ;;
        *)
            log "removing console user $_console_user"
            deluser "$_console_user" >/dev/null 2>&1
            ;;
        esac
    fi

    rm -f "$INITD" "$CONFIG" "$LOOP_BIN" "$HB_BIN" "$UNINSTALL_BIN"
    rm -rf "$STATE_DIR"
    rm -f "$KEY_PATH"
    rm -f /tmp/tunnelgate-exchange.* /tmp/tunnelgate-report.* /tmp/tunnelgate-heartbeat-* 2>/dev/null

    if [ "$PURGE" = "1" ]; then
        case "$(detect_pkg_manager)" in
        apk) apk del openssh-client >/dev/null 2>&1 || log "warning: could not remove openssh-client" ;;
        opkg) opkg remove openssh-client >/dev/null 2>&1 || log "warning: could not remove openssh-client" ;;
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
        # Say this out loud, once, when the setting cannot deliver what its name promises.
        if [ "$TLS_VERIFY" = "1" ] && tls_stack_cannot_verify; then
            log "WARNING: on OpenWrt $(detect_openwrt_version) the fetcher cannot check a certificate chain: it accepts self-signed certificates (a wrong hostname is still caught). tls_verify=1 is recorded, but it is not being enforced. 21.02 or newer is required for real verification"
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
