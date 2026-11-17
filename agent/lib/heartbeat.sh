#!/bin/sh
# TunnelGate - heartbeat sender (procd instance "heartbeat", runs every 60 s).
#
# Responsibilities
#   * POST metadata to the panel so a quiet tunnel still proves the router is alive;
#   * consume the console key registration delivered in the response: when the serial in
#     UCI is behind the serial shipped by the panel, rewrite the tunnelgate-console line in
#     /etc/dropbear/authorized_keys, bump the stored serial and report console_installed.
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
    if command -v curl >/dev/null 2>&1; then
        curl -q -sS -o "$4" -w '%{http_code}' --max-time 30 -X POST \
            -H "Content-Type: application/json" \
            -H "X-Api-Token: $2" \
            --data-binary "@$3" \
            "$1" 2>/dev/null
        return 0
    fi
    wget -q -O "$4" \
        --header "Content-Type: application/json" \
        --header "X-Api-Token: $2" \
        --post-file="$3" \
        --timeout=30 -S "$1" 2>&1 |
        sed -n 's/.*HTTP\/1\.[01] \([0-9][0-9][0-9]\).*/\1/p' | tail -n 1
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

http_code=$(send_heartbeat 0)
case "$http_code" in
2??) ;;
"") log "heartbeat failed: no HTTP status (DNS, TLS or network problem)"; exit 0 ;;
*) log "heartbeat failed: HTTP $http_code"; exit 0 ;;
esac

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
