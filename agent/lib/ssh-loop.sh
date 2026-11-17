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
