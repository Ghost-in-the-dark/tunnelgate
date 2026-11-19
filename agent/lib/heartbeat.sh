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
