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
