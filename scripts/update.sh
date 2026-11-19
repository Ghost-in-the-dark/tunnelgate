#!/bin/sh
set -eu

# ---------------------------------------------------------------------------
# TunnelGate update script - fetch a release, rebuild what must be rebuilt,
# refuse to run ahead of the database, restart, and verify.
#
#   curl -fsSL https://raw.githubusercontent.com/Ghost-in-the-dark/tunnelgate/main/scripts/update.sh \
#     | sudo sh -s -- --ref v1.2.0
#
# "curl ... | sudo sh" is the supported form, so stdin IS this script: every
# prompt reads /dev/tty, never stdin (a plain read would eat the next line of
# this file and die in a way that looks like a bad answer).
#
# Why the order below is what it is:
#   * the backup comes first, before anything is resolved or written: a backup
#     taken after the first mutation is a record of the damage, not a way out.
#   * the new code is STAGED and exercised - dependencies, schema check, SPA -
#     while the old panel keeps serving. Nothing is swapped in until all three
#     have passed, and the schema check runs against a SNAPSHOT of the live
#     database, so a release that needs a new column stops before the database
#     is touched at all.
#   * the swap is rsync --delete, so a file deleted upstream disappears here too;
#     two versions of the app importing each other is not a failure mode worth
#     leaving open.
#   * the restart is proved by asking /api/v1/health for the version, not by
#     systemctl returning 0. A panel that dies on its first bind is ACTIVE for a
#     second and then in auto-restart, which looks started.
#
# TunnelGate has no migration engine by design (single-file SQLite, additive
# changes only). That is why a schema change STOPS the update.
# ---------------------------------------------------------------------------

SERVICE=tunnelgate
REF=""
SOURCE=""
REPO_URL=https://github.com/Ghost-in-the-dark/tunnelgate
INSTALL_DIR=""
DATA_DIR=""
ENV_FILE=""
RUN_USER=""
RUN_GROUP=""
DB_FILE=""
BACKUP_ROOT=/var/backups/tunnelgate
DRY_RUN=0
NON_INTERACTIVE=0
SKIP_BACKUP=0
SKIP_SCHEMA_CHECK=0
FORCE=0
CHECK_ONLY=0
ASSUME_YES=0
KEEP_SOURCE=0
SOURCE_TMP=""
STAGE=""
CODE_DIR=""
CODE_MODE=""
BACKUP_DIR=""
SCHEMA_DB=""
SCHEMA_TMP=""
OLD_VERSION=""
NEW_VERSION=""
OLD_REV=""
SWAPPED=0

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Every mutation goes through this, so --dry-run is honest rather than aspirational.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  [dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

need_value() {
    if [ $# -lt 2 ] || [ -z "$2" ]; then
        die "$1 needs a value"
    fi
}

# Prompts are only attempted when there is a terminal AND output is not
# redirected: "sudo sh -s -- --ref v1 > update.log" must not stop and wait for an
# answer nobody can see.
have_tty() {
    [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ]
}

ask() {   # ask <prompt> <default>; prints the answer (or the default)
    if ! have_tty; then
        printf '%s' "$2"
        return 0
    fi
    printf '%s ' "$1" >/dev/tty
    ask_reply=""
    read -r ask_reply </dev/tty || ask_reply=""
    [ -n "$ask_reply" ] || ask_reply=$2
    printf '%s' "$ask_reply"
}

usage() {
    cat <<'TUNNELGATE_UPDATE_USAGE_EOF'
TunnelGate update - fetch a release, rebuild, check the schema, restart, verify.

  curl -fsSL https://raw.githubusercontent.com/Ghost-in-the-dark/tunnelgate/main/scripts/update.sh \
    | sudo sh -s -- --ref v1.2.0

  sudo ./scripts/update.sh --ref v1.2.0 --source .     from a checkout
  sudo ./scripts/update.sh --check-only                what is installed, what is new

WHAT IT CHANGES
  the code in the install dir, the venv's packages, web/dist, and a restart.
  It never rewrites /etc/tunnelgate.env, never touches the data directory, nginx
  or the sshd drop-in: a release that needs those says so in its release notes.

WHAT IT REFUSES
  a release whose schema needs hand work. The check runs against a SNAPSHOT of the
  live database, so nothing is mutated before the restart. Apply the printed
  ALTER TABLE statements, then re-run with --skip-schema-check.

OPTIONS
  --ref REF              git tag, branch or commit to install  (default: latest release)
  --service-name NAME    systemd unit to update                (default tunnelgate)
  --install-dir DIR      override the directory the unit runs from
  --data-dir DIR         override the data directory
  --env-file FILE        override the unit's EnvironmentFile
  --backup-root DIR      where backups go        (default /var/backups/tunnelgate)
  --source DIR           update from this checkout instead of downloading
  --repo-url URL         repository to download from
  --check-only           report versions, change nothing
  --skip-backup          do not back up                  (NOT recommended)
  --skip-schema-check    install without running the schema check
  --force                proceed when the version is unchanged or the tree is dirty
  --keep-source          keep the downloaded tree (removed otherwise)
  --non-interactive      never prompt; take the documented default
  --yes                  do not ask for confirmation
  --dry-run              print the plan, change nothing
  -h, --help             this text

EXIT CODES
  0  updated (or already current), panel healthy
  1  stopped: a precondition failed, the schema needs hand work, or the panel did
     not come back (the previous version is restored and restarted)
  2  bad arguments

ROLLBACK BY HAND
  the previous code is in <backup-root>/update-<stamp>/code.tar.gz and the database
  beside it. The unit is NOT reinstalled by an update, so:
    tar -xzf <backup>/code.tar.gz -C <install-dir> && systemctl restart tunnelgate
TUNNELGATE_UPDATE_USAGE_EOF
    exit "${1:-0}"
}

# ------------------------------------------------------------------ arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) need_value "$@"; REF=$2; shift 2 ;;
        --ref=*) REF=${1#*=}; shift ;;
        --service-name) need_value "$@"; SERVICE=$2; shift 2 ;;
        --service-name=*) SERVICE=${1#*=}; shift ;;
        --install-dir) need_value "$@"; INSTALL_DIR=$2; shift 2 ;;
        --install-dir=*) INSTALL_DIR=${1#*=}; shift ;;
        --data-dir) need_value "$@"; DATA_DIR=$2; shift 2 ;;
        --data-dir=*) DATA_DIR=${1#*=}; shift ;;
        --env-file) need_value "$@"; ENV_FILE=$2; shift 2 ;;
        --env-file=*) ENV_FILE=${1#*=}; shift ;;
        --backup-root) need_value "$@"; BACKUP_ROOT=$2; shift 2 ;;
        --backup-root=*) BACKUP_ROOT=${1#*=}; shift ;;
        --source) need_value "$@"; SOURCE=$2; shift 2 ;;
        --source=*) SOURCE=${1#*=}; shift ;;
        --repo-url) need_value "$@"; REPO_URL=$2; shift 2 ;;
        --repo-url=*) REPO_URL=${1#*=}; shift ;;
        --check-only) CHECK_ONLY=1; shift ;;
        --skip-backup) SKIP_BACKUP=1; shift ;;
        --skip-schema-check) SKIP_SCHEMA_CHECK=1; shift ;;
        --force) FORCE=1; shift ;;
        --keep-source) KEEP_SOURCE=1; shift ;;
        --non-interactive) NON_INTERACTIVE=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; echo "try --help" >&2; exit 2 ;;
    esac
done

# Bad arguments exit 2, not 1: a caller scripting this needs to tell "you asked me
# something impossible" apart from "I tried and stopped safely".
bad_arg() { printf 'error: %s\n' "$*" >&2; exit 2; }

case "$SERVICE" in
    *[!a-zA-Z0-9_.-]*|'') bad_arg "--service-name may contain only letters, digits, dot, dash and underscore" ;;
esac
case "$REF" in
    *[!a-zA-Z0-9._/-]*) bad_arg "--ref may contain only letters, digits, dot, dash, slash and underscore" ;;
esac
if [ -n "$INSTALL_DIR" ]; then
    case "$INSTALL_DIR" in
        /*) ;;
        *) bad_arg "--install-dir must be an absolute path: $INSTALL_DIR" ;;
    esac
fi
if [ -n "$DATA_DIR" ]; then
    case "$DATA_DIR" in
        /*) ;;
        *) bad_arg "--data-dir must be an absolute path: $DATA_DIR" ;;
    esac
fi

# A dry run changes nothing, so it must stay usable without sudo: an operator
# reading the plan before handing root to a script is the point, not an error.
if [ "$DRY_RUN" -eq 1 ]; then
    [ "$(id -u)" -eq 0 ] || warn "dry run as a non-root user: the plan is complete, but the real run needs root"
else
    [ "$(id -u)" -eq 0 ] || die "run this as root: it reinstalls the venv's packages, rewrites the install dir and restarts a system unit"
fi

# The downloaded tree, the staging tree, the schema snapshot and nothing else are
# ours to remove, and each removal is guarded by a pattern that only matches a
# path this script created - so a bad variable can never turn cleanup into an
# rm -rf of /opt.
cleanup() {
    status=$?
    if [ "$KEEP_SOURCE" -eq 0 ] && [ -n "$SOURCE_TMP" ] && [ -d "$SOURCE_TMP" ]; then
        case "$SOURCE_TMP" in
            */tunnelgate-update-src.*) rm -rf -- "$SOURCE_TMP" ;;
        esac
    fi
    # Staging survives a failed run on purpose: it is the tree that failed, and
    # deleting it removes the only evidence of why.
    if [ "$status" -eq 0 ] && [ -n "$STAGE" ] && [ -d "$STAGE" ]; then
        case "$STAGE" in
            */.update-staging) rm -rf -- "$STAGE" ;;
        esac
    fi
    if [ -n "$SCHEMA_TMP" ] && [ -d "$SCHEMA_TMP" ]; then
        case "$SCHEMA_TMP" in
            */tunnelgate-update-probe.*) rm -rf -- "$SCHEMA_TMP" ;;
        esac
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# ------------------------------------------------------------------ 1. find it
# An updater that guesses the install directory is worse than none: it would
# "update" a directory the running unit never reads, report success, and leave the
# host on the old code. systemd already knows the truth, so ask it.
say "finding the installation"
command -v systemctl >/dev/null 2>&1 || die "systemd is required: this script updates a systemd service"
if ! systemctl cat "$SERVICE.service" >/dev/null 2>&1; then
    die "no $SERVICE.service on this host.
       Pass --service-name NAME if the unit is named differently, or install first:
       scripts/quick-install.sh (behind your own proxy) or
       scripts/setup-server.sh (TLS on this host)."
fi
UNIT_FILE=$(systemctl show "$SERVICE.service" -p FragmentPath --value 2>/dev/null || true)
EXEC_START=$(systemctl show "$SERVICE.service" -p ExecStart --value 2>/dev/null || true)
UNIT_USER=$(systemctl show "$SERVICE.service" -p User --value 2>/dev/null || true)
UNIT_WORKDIR=$(systemctl show "$SERVICE.service" -p WorkingDirectory --value 2>/dev/null || true)
UNIT_ENVFILE=$(systemctl show "$SERVICE.service" -p EnvironmentFiles --value 2>/dev/null || true)

# ExecStart= arrives as "{ path=/opt/tunnelgate/.venv/bin/uvicorn ; argv[]=... }".
EXEC_PATH=$(printf '%s' "$EXEC_START" | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1)
if [ -z "$EXEC_PATH" ] && [ -n "$UNIT_FILE" ] && [ -r "$UNIT_FILE" ]; then
    # A unit that was installed but never started has no runtime properties yet.
    EXEC_PATH=$(sed -n 's/^ExecStart=//p' "$UNIT_FILE" | head -n1 | awk '{print $1}')
fi
[ -n "$EXEC_PATH" ] || die "cannot read ExecStart= from $SERVICE.service (unit: ${UNIT_FILE:-unknown}). Pass --install-dir DIR."

case "$EXEC_PATH" in
    */.venv/bin/*) GUESSED_INSTALL=$(dirname "$(dirname "$EXEC_PATH")") ;;
    *) die "ExecStart does not run from a virtualenv: $EXEC_PATH
       This does not look like an installation made by scripts/quick-install.sh or
       scripts/setup-server.sh. Pass --install-dir DIR and --env-file FILE." ;;
esac

# EnvironmentFiles= arrives as "/etc/tunnelgate.env (ignore_errors=yes)".
UNIT_ENVFILE=${UNIT_ENVFILE%% (ignore_errors*}

if [ -z "$INSTALL_DIR" ]; then
    if [ -n "$UNIT_WORKDIR" ]; then
        INSTALL_DIR=$UNIT_WORKDIR
    else
        INSTALL_DIR=$GUESSED_INSTALL
    fi
fi
if [ -z "$ENV_FILE" ]; then
    if [ -n "$UNIT_ENVFILE" ]; then
        ENV_FILE=$UNIT_ENVFILE
    elif [ -n "$UNIT_FILE" ] && [ -r "$UNIT_FILE" ]; then
        ENV_FILE=$(sed -n 's/^EnvironmentFile=-*//p' "$UNIT_FILE" | head -n1)
    fi
fi
[ -n "$ENV_FILE" ] || die "cannot find the unit's EnvironmentFile. Pass --env-file FILE."
[ -r "$ENV_FILE" ] || die "$ENV_FILE is not readable. Run this as root."
if [ -z "$RUN_USER" ]; then
    if [ -n "$UNIT_USER" ]; then
        RUN_USER=$UNIT_USER
    else
        RUN_USER=root   # a unit without User= runs as root
    fi
fi
RUN_GROUP=$(id -gn "$RUN_USER" 2>/dev/null || printf '%s' "$RUN_USER")

[ -d "$INSTALL_DIR" ] || die "$INSTALL_DIR does not exist (from the unit's WorkingDirectory=). Pass --install-dir DIR."
VENV_PY="$INSTALL_DIR/.venv/bin/python"
[ -x "$VENV_PY" ] || die "$VENV_PY is missing: $INSTALL_DIR is not a virtualenv installation. Pass --install-dir DIR."

# The panel is configured by this file and the database path lives in it, so it is
# sourced the same way the service receives it. As root: the file is 0600.
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

if [ -z "$DATA_DIR" ]; then
    DATA_DIR=${TUNNELGATE_DATA_DIR:-}
fi
if [ -z "$DB_FILE" ]; then
    case "${TUNNELGATE_DB_URL:-}" in
        sqlite:///*) DB_FILE=${TUNNELGATE_DB_URL#sqlite:///} ;;
        "") DB_FILE="" ;;
        *) warn "TUNNELGATE_DB_URL is not SQLite (${TUNNELGATE_DB_URL%%:*}): no database backup will be taken"
           warn "  back it up with pg_dump/mysqldump yourself before updating"
           DB_FILE="" ;;
    esac
fi
if [ -z "$DATA_DIR" ] && [ -n "$DB_FILE" ]; then
    DATA_DIR=$(dirname "$DB_FILE")
fi
if [ -z "$DATA_DIR" ]; then
    DATA_DIR=$INSTALL_DIR/data
fi

OLD_VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$INSTALL_DIR/app/__init__.py" 2>/dev/null | head -n1)
[ -n "$OLD_VERSION" ] || OLD_VERSION=unknown

printf '     service      %s.service\n' "$SERVICE"
printf '     code         %s\n' "$INSTALL_DIR"
printf '     data         %s\n' "$DATA_DIR"
printf '     database     %s\n' "${DB_FILE:-none}"
printf '     environment  %s\n' "$ENV_FILE"
printf '     service user %s\n' "$RUN_USER"
printf '     installed    %s\n' "$OLD_VERSION"

# git refuses to work in a directory owned by another user ("dubious ownership"),
# which is EXACTLY the production layout: root running this script over a tree the
# service account owns. The fix is passed per invocation as -c safe.directory=...
# rather than written into the host's global git config: an update script has no
# business editing /root/.gitconfig, and the exception should stop applying when
# this script does.
git_install() {
    git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" "$@"
}

if [ -d "$INSTALL_DIR/.git" ]; then
    CODE_MODE=git
    OLD_REV=$(git_install rev-parse HEAD 2>/dev/null || true)
else
    CODE_MODE=archive
fi

# ------------------------------------------------------------------ 2. what is new
say "resolving the target release"
if [ -n "$SOURCE" ]; then
    # --source names the tree directly; asking GitHub for a release would print a
    # ref that has nothing to do with what is being installed.
    REF=$SOURCE
elif [ -z "$REF" ]; then
    # A release tag, because an updater that silently installs an unreleased main
    # is how a fleet ends up on a commit nobody chose. Falls back to main only
    # when GitHub cannot be asked, and says so.
    API_URL=$(printf '%s' "$REPO_URL" | sed -e 's#^https://github.com/#https://api.github.com/repos/#' -e 's#/$##')
    REF=$(curl -fsSL --max-time 15 "$API_URL/releases/latest" 2>/dev/null \
            | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1 || true)
    if [ -n "$REF" ]; then
        ok "latest release is $REF"
    else
        REF=main
        warn "could not ask GitHub for the latest release; falling back to branch $REF"
        warn "  pass --ref vX.Y.Z to pin a release"
    fi
fi

if [ -n "$SOURCE" ]; then
    [ -f "$SOURCE/requirements.txt" ] || die "--source $SOURCE does not look like a TunnelGate checkout (no requirements.txt)"
    CODE_DIR=$(cd "$SOURCE" && pwd)
    CODE_MODE=source
elif [ "$CODE_MODE" = git ]; then
    git_install fetch --tags --prune --quiet || die "git fetch failed in $INSTALL_DIR"
    git_install rev-parse --verify --quiet "$REF" >/dev/null 2>&1 || \
        die "$REF is not a tag, branch or commit in $INSTALL_DIR.
       Fetch it first (git fetch --tags), or pass --ref with one that exists."
    # Extracted, not checked out: the swap must not happen until the new code has
    # passed the schema check and the SPA has built.
    STAGE=$INSTALL_DIR/.update-staging
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -rf -- "$STAGE"
        mkdir -p "$STAGE"
        git_install archive --format=tar "$REF" | tar -x -C "$STAGE" || \
            die "could not extract $REF from $INSTALL_DIR"
    fi
    CODE_DIR=$STAGE
else
    command -v curl >/dev/null 2>&1 || die "curl is needed to download the release"
    command -v tar >/dev/null 2>&1 || die "tar is needed to unpack the release"
    SOURCE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/tunnelgate-update-src.XXXXXX")
    say "downloading $REF from $REPO_URL"
    if ! curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 \
            "$REPO_URL/archive/$REF.tar.gz" | tar -xzf - -C "$SOURCE_TMP" --strip-components=1; then
        die "could not download $REPO_URL (ref: $REF).
       Pass --ref with an existing tag, --repo-url for a fork, or --source DIR."
    fi
    [ -f "$SOURCE_TMP/requirements.txt" ] || die "the archive for $REF is not a TunnelGate tree (no requirements.txt)"
    # mktemp -d is 0700 root, and the schema check - the SPA build too - runs as the
    # SERVICE account. Hand the downloaded tree over, or the check cannot even cd
    # into it and dies with "No module named 'app'", which reads like a broken
    # release rather than a permissions artefact. This is a copy of public source,
    # so the service account owning it costs nothing.
    if [ "$RUN_USER" != root ]; then
        chown -R "$RUN_USER:$RUN_GROUP" "$SOURCE_TMP" 2>/dev/null || \
            die "could not hand $SOURCE_TMP to $RUN_USER"
    fi
    CODE_DIR=$SOURCE_TMP
fi

NEW_VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$CODE_DIR/app/__init__.py" 2>/dev/null | head -n1)
[ -n "$NEW_VERSION" ] || NEW_VERSION=unknown
ok "target is $REF ($NEW_VERSION)"

if [ "$CODE_MODE" != source ] && [ "$NEW_VERSION" = "$OLD_VERSION" ] && [ "$FORCE" -eq 0 ]; then
    printf '\n%s is already at %s. Nothing to do.\n' "$SERVICE" "$OLD_VERSION" >&2
    printf 'Use --force to reinstall the same version, or --ref to choose another.\n' >&2
    exit 0
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
    printf '\ninstalled %s -> available %s (%s)\n' "$OLD_VERSION" "$NEW_VERSION" "$REF"
    printf 'Nothing was changed (--check-only).\n'
    exit 0
fi

if [ "$CODE_MODE" = git ] && [ "$FORCE" -eq 0 ]; then
    # .update-staging lives INSIDE the install directory (same filesystem, so the
    # swap is a rename-free copy and a half-written tree is never mounted), which
    # makes it an untracked entry that would fail the very dirty check meant to
    # protect the tree. It is this script's own scratch space, not an operator's
    # edit, so it is excluded rather than treated as a local change.
    dirty=$(git_install status --porcelain -- . ':(exclude).update-staging' 2>/dev/null | head -n 5 || true)
    if [ -n "$dirty" ]; then
        printf 'the checkout in %s has local changes:\n' "$INSTALL_DIR" >&2
        printf '%s\n' "$dirty" >&2
        die "commit or stash them first, or pass --force (they will be overwritten).
       An update that silently discards local edits is not an update."
    fi
fi

if [ "$ASSUME_YES" -eq 0 ] && have_tty; then
    printf '\nUpdate %s: %s -> %s (%s)? [Y/n]: ' "$SERVICE" "$OLD_VERSION" "$NEW_VERSION" "$REF" >/dev/tty
    reply=""
    read -r reply </dev/tty || reply=""
    case "$reply" in
        n|N|no|NO) printf 'aborted; nothing was changed.\n' >&2; exit 0 ;;
    esac
fi

STAMP=$(date -u '+%Y%m%dT%H%M%SZ')

# Run a command as the account the panel runs as. The database, the venv and
# web/dist must stay owned by that account: a root-owned file there is a
# permission failure on the next start, not a cosmetic difference.
as_panel() {
    if [ "$RUN_USER" = root ]; then
        "$@"
        return $?
    fi
    runuser -u "$RUN_USER" --preserve-environment -- "$@"
}

# ------------------------------------------------------------------ 3. backup
# Before anything else is written, and before the schema snapshot: a backup taken
# after the first mutation is a record of the damage, not a way out of it.
if [ "$SKIP_BACKUP" -eq 1 ]; then
    warn "skipping the backup (--skip-backup); there will be no way back"
elif [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] back up the database, keys, env file and code into %s/update-%s\n' "$BACKUP_ROOT" "$STAMP"
else
    say "backing up"
    mkdir -p "$BACKUP_ROOT"
    chmod 0700 "$BACKUP_ROOT"
    BACKUP_DIR=$BACKUP_ROOT/update-$STAMP
    install -d -m 0700 "$BACKUP_DIR"
    if [ -n "$DB_FILE" ] && [ -f "$DB_FILE" ]; then
        if command -v sqlite3 >/dev/null 2>&1; then
            # .backup, not cp: the panel is running, and a copied -wal file is not a
            # consistent database. This is the documented way to take one live.
            sqlite3 "$DB_FILE" ".backup '$BACKUP_DIR/tunnelgate.db'" || \
                die "the database backup failed; nothing was changed"
            ok "database -> $BACKUP_DIR/tunnelgate.db"
        else
            cp -p "$DB_FILE" "$BACKUP_DIR/tunnelgate.db"
            [ -f "$DB_FILE-wal" ] && cp -p "$DB_FILE-wal" "$BACKUP_DIR/tunnelgate.db-wal"
            [ -f "$DB_FILE-shm" ] && cp -p "$DB_FILE-shm" "$BACKUP_DIR/tunnelgate.db-shm"
            warn "sqlite3 is not installed, so the database was copied (not snapshotted)"
        fi
    else
        warn "no database at ${DB_FILE:-<unknown>}; nothing to back up there"
    fi
    if [ -f "$ENV_FILE" ]; then
        cp -p "$ENV_FILE" "$BACKUP_DIR/tunnelgate.env"
        chmod 0600 "$BACKUP_DIR/tunnelgate.env"
    fi
    if [ -f "$DATA_DIR/.ssh/authorized_keys" ]; then
        cp -p "$DATA_DIR/.ssh/authorized_keys" "$BACKUP_DIR/authorized_keys"
    fi
    for f in /etc/nginx/tunnelgate/routes.conf /etc/nginx/tunnelgate/routes.auth.conf; do
        if [ -f "$f" ]; then
            cp -p "$f" "$BACKUP_DIR/$(basename "$f")"
        fi
    done
    # The venv's exact package set, so a failed schema check can put it back.
    "$INSTALL_DIR/.venv/bin/pip" freeze 2>/dev/null >"$BACKUP_DIR/pip-freeze.txt" || true
    # The code, so a failed start can be undone without a network round trip.
    tar -czf "$BACKUP_DIR/code.tar.gz" -C "$INSTALL_DIR" \
        --exclude './.venv' --exclude './web/node_modules' --exclude './data' \
        --exclude './.git' --exclude './.update-staging' . 2>/dev/null || \
        die "could not archive $INSTALL_DIR; nothing was changed"
    ok "code -> $BACKUP_DIR/code.tar.gz"
    printf '     roll back with: tar -xzf %s/code.tar.gz -C %s\n' "$BACKUP_DIR" "$INSTALL_DIR"
fi

# ------------------------------------------------------------------ 4. deps
# The new code may import a library the old one did not, and the schema check IS
# the new code, so this has to come first. It is the one step that changes the
# running system before the swap - hence the pip freeze above and the restore
# below when the schema check then refuses the release.
say "installing the Python dependencies"
if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] %s install -r %s/requirements.txt\n' "$INSTALL_DIR/.venv/bin/pip" "$CODE_DIR"
else
    if ! "$INSTALL_DIR/.venv/bin/pip" install --quiet --disable-pip-version-check \
            -r "$CODE_DIR/requirements.txt"; then
        warn "pip install failed; restoring the previous package set"
        if [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/pip-freeze.txt" ]; then
            "$INSTALL_DIR/.venv/bin/pip" install --quiet --disable-pip-version-check \
                -r "$BACKUP_DIR/pip-freeze.txt" >/dev/null 2>&1 || true
        fi
        die "dependency install failed. The code, the database and web/dist are
       unchanged; the venv was put back to the set recorded in
       ${BACKUP_DIR:-<no backup>}/pip-freeze.txt."
    fi
    ok "dependencies up to date"
fi

# ------------------------------------------------------------------ 5. schema
# The step that makes an updater trustworthy. The NEW code's check-schema runs
# against a SNAPSHOT of the live database, so a release that needs a column stops
# here with the old panel still serving and the live database byte-identical.
say "checking the database schema"
if [ -n "$DB_FILE" ] && [ -f "$DB_FILE" ]; then
    if [ "$DRY_RUN" -eq 0 ]; then
        if command -v sqlite3 >/dev/null 2>&1; then
            SCHEMA_TMP=$(mktemp -d "${TMPDIR:-/tmp}/tunnelgate-update-probe.XXXXXX")
            if sqlite3 "$DB_FILE" ".backup '$SCHEMA_TMP/probe.db'" 2>/dev/null; then
                SCHEMA_DB=$SCHEMA_TMP/probe.db
            else
                cp "$DB_FILE" "$SCHEMA_TMP/probe.db" 2>/dev/null && SCHEMA_DB=$SCHEMA_TMP/probe.db
            fi
        fi
        # mktemp -d is 0700 root, and the check runs as the SERVICE account: the
        # snapshot has to be handed over or the check cannot even open its own
        # database - which then reads exactly like schema drift and would block
        # every update with a false alarm. It is a copy of production data, so it
        # goes to the service account alone, never world-readable.
        if [ -n "$SCHEMA_DB" ]; then
            if [ "$RUN_USER" != root ]; then
                chown -R "$RUN_USER:$RUN_GROUP" "$SCHEMA_TMP" 2>/dev/null || true
            fi
            chmod 0700 "$SCHEMA_TMP" 2>/dev/null || true
            if ! as_panel test -r "$SCHEMA_DB" 2>/dev/null; then
                warn "the schema snapshot is not readable by $RUN_USER: the check is skipped"
                warn "  check by hand: $INSTALL_DIR/.venv/bin/python -m app.cli check-schema"
                SCHEMA_DB=""
            fi
        fi
        # Without sqlite3 there is no safe snapshot, and checking the live file
        # would leave check-schema's init-db free to create tables in production.
        if [ -z "$SCHEMA_DB" ]; then
            warn "no sqlite3, so no consistent snapshot: the schema check is skipped"
            warn "  install sqlite3 and re-run, or check by hand with:"
            warn "  $INSTALL_DIR/.venv/bin/python -m app.cli check-schema"
        fi
    fi
fi

schema_ok=0
if [ "$SKIP_SCHEMA_CHECK" -eq 1 ]; then
    warn "skipped (--skip-schema-check): the panel may start and then fail on its first write"
    schema_ok=1
elif [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] (as %s) check-schema from %s against a snapshot of %s\n' \
        "$RUN_USER" "$CODE_DIR" "${DB_FILE:-the configured database}"
    schema_ok=1
elif [ -z "$SCHEMA_DB" ]; then
    schema_ok=1
else
    restore_venv() {
        if [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/pip-freeze.txt" ]; then
            "$INSTALL_DIR/.venv/bin/pip" install --quiet --disable-pip-version-check \
                -r "$BACKUP_DIR/pip-freeze.txt" >/dev/null 2>&1 || true
            ok "the venv was put back to its previous package set"
        fi
    }
    schema_out=$(cd "$CODE_DIR" && as_panel env \
        "TUNNELGATE_DB_URL=sqlite:///$SCHEMA_DB" \
        "TUNNELGATE_DATA_DIR=$SCHEMA_TMP" \
        "$VENV_PY" -m app.cli check-schema 2>&1) && schema_ok=1 || schema_ok=0
    printf '%s\n' "$schema_out" | sed -e 's/^/     /'
    # Distinguish "the release really does need hand work" from "the check itself
    # could not run". Reporting a broken probe as schema drift would tell an
    # operator to write ALTER TABLEs for a schema that is already fine.
    if [ "$schema_ok" -eq 0 ] && ! printf '%s' "$schema_out" | grep -q 'ALTER TABLE'; then
        restore_venv
        die "the schema check could not run (see above); nothing was installed.
       The previous version is still running and the live database is untouched.
       Check by hand, then re-run with --skip-schema-check:
         cd $INSTALL_DIR && .venv/bin/python -m app.cli check-schema"
    fi
    if [ "$schema_ok" -eq 0 ]; then
        restore_venv
        printf '\n' >&2
        cat >&2 <<SCHEMA_STOP
this release needs database changes that init-db cannot make. Nothing was
installed: the panel is still running the previous version, and the LIVE database
was never written to - the check ran against a snapshot.

There is no migration engine by design (single-file SQLite, additive changes
only). Apply the statements printed above, in a transaction, with the backup this
script just took:

    sqlite3 ${DB_FILE:-<db>} ".backup '${DB_FILE:-<db>}.before-$STAMP'"
    sqlite3 ${DB_FILE:-<db>} "ALTER TABLE ...;"     # the lines printed above

Then run this again, skipping only the check you have just done by hand:

    ... update.sh --ref $REF --skip-schema-check

SCHEMA_STOP
        die "stopped before installing: the database schema needs hand work first"
    fi
    if printf '%s' "$schema_out" | grep -qi 'not in the models'; then
        warn "the database has columns the new models do not: usually a rollback, or a hand edit"
    fi
    ok "schema is compatible with $NEW_VERSION (checked against a snapshot)"
fi

# ------------------------------------------------------------------ 6. SPA
# web/dist is not in the repository, so a code-only update ships an API and no UI
# - and an old dist against a new API is how a panel starts rendering blank.
say "building the SPA"
if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] npm ci && npm run build in %s/web\n' "$CODE_DIR"
elif ! command -v npm >/dev/null 2>&1; then
    warn "npm is not installed: the existing web/dist is kept and may not match the new API"
    warn "  install nodejs+npm and run again, or build it by hand:"
    warn "  cd $INSTALL_DIR/web && npm ci && npm run build"
elif [ ! -f "$CODE_DIR/web/package.json" ]; then
    warn "no web/package.json in the staged tree; the existing web/dist is kept"
else
    # Built as root, deliberately. The staging tree is disposed of after the swap,
    # so owning it as the service account buys nothing and would rewrite the
    # ownership of a --source checkout the operator may keep using. What must end
    # up readable by the panel is web/dist AFTER the copy, and the swap chowns the
    # install dir for exactly that reason. A root-run npm still writes files the
    # panel can read (0644), and npm needs no HOME of the service account here.
    if npm_config_cache="${TMPDIR:-/tmp}/npm-cache" sh -c \
            "cd '$CODE_DIR/web' && npm ci --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1"; then
        ok "SPA built into web/dist"
    elif [ -f "$INSTALL_DIR/web/dist/index.html" ]; then
        warn "the SPA build failed; the existing web/dist is kept and may not match the new API"
        warn "  build it by hand to see why: cd $CODE_DIR/web && npm ci && npm run build"
    else
        die "the SPA build failed and there is no previous web/dist to fall back on.
       Nothing was installed. Build it by hand to see why:
         cd $CODE_DIR/web && npm ci && npm run build"
    fi
fi

# ------------------------------------------------------------------ 7. swap
# rsync --delete from the staged tree, so a file deleted upstream disappears here
# too. Excluded are the things this directory OWNS rather than receives: the venv
# is not portable, node_modules is rebuilt by npm ci, data is not source, and
# .update-staging is the tree being copied from.
say "installing the new code"
if [ "$CODE_DIR" = "$INSTALL_DIR" ]; then
    ok "already current: --source is the install directory"
elif [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] rsync -a --delete %s/ -> %s/ (keeps .venv, data, web/node_modules)\n' "$CODE_DIR" "$INSTALL_DIR"
else
    rsync -a --delete \
        --exclude '.venv/' --exclude 'data/' --exclude 'web/node_modules/' \
        --exclude '.git/' --exclude '.update-staging/' \
        --exclude '__pycache__/' --exclude '*.pyc' \
        --exclude '*.db' --exclude '*.db-wal' --exclude '*.db-shm' \
        "$CODE_DIR/" "$INSTALL_DIR/" || die "rsync failed; the code may be half-updated.
       Roll back with:
         tar -xzf ${BACKUP_DIR:-<backup>}/code.tar.gz -C $INSTALL_DIR"
    SWAPPED=1
    chown -R "$RUN_USER:$RUN_GROUP" "$INSTALL_DIR"
    if [ "$CODE_MODE" = git ]; then
        # The files already match, so this only moves HEAD and the index. A failure
        # here is cosmetic, not fatal: the installed code is what runs.
        git_install checkout --quiet "$REF" 2>/dev/null || \
            warn "could not move the git checkout to $REF; the files are installed anyway"
        ok "code installed ($(git_install rev-parse --short HEAD 2>/dev/null || printf '%s' "$REF"))"
    else
        ok "code installed"
    fi
    rm -rf -- "$STAGE" 2>/dev/null || true
    STAGE=""
fi

# ------------------------------------------------------------------ 8. restart
restart_panel() {
    systemctl restart "$SERVICE"
}

# "restart", not "reload": uvicorn without --reload keeps its already-imported
# modules, so a reload can leave the old code running behind a new version number.
health_url() {
    case "${TUNNELGATE_PANEL_URL:-}" in
        http://*|https://*) printf '%s/api/v1/health' "${TUNNELGATE_PANEL_URL%/}" ;;
        *) printf 'http://127.0.0.1:%s/api/v1/health' "${TUNNELGATE_PORT:-8080}" ;;
    esac
}

probe_version() {   # probe_version <url> -> the version, or nothing when it does not answer
    body=$(curl -fsS --max-time 3 "$1" 2>/dev/null || true)
    [ -n "$body" ] || return 0
    printf '%s' "$body" | sed -n 's/.*"version":[[:space:]]*"\([^"]*\)".*/\1/p'
}

# Wait for the health endpoint, up to 20 seconds. Prints the version it saw
# and returns 0; prints nothing and returns 1 otherwise. Extracted because the
# rollback needs exactly the same wait: probing ONCE right after "systemctl
# restart" returns before uvicorn has bound its socket, which made a rollback that
# HAD worked report itself as a double failure - the worst message to give, because
# it sends an operator off to repair a host that is already healthy.
wait_for_health() {   # wait_for_health <url> [attempts]
    wfh_url=$1
    wfh_left=$2
    while [ "$wfh_left" -gt 0 ]; do
        wfh_version=$(probe_version "$wfh_url")
        if [ -n "$wfh_version" ]; then
            printf '%s' "$wfh_version"
            return 0
        fi
        wfh_left=$((wfh_left - 1))
        [ "$wfh_left" -gt 0 ] && sleep 1
    done
    return 1
}

say "restarting $SERVICE"
url=$(health_url)
if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] systemctl restart %s, then poll %s\n' "$SERVICE" "$url"
else
    systemctl daemon-reload
    restart_panel || die "systemctl restart $SERVICE failed. The new code is installed but not running.
       Roll back with:
         tar -xzf ${BACKUP_DIR:-<backup>}/code.tar.gz -C $INSTALL_DIR && systemctl restart $SERVICE"
    running_version=$(wait_for_health "$url" 20) && ready=1 || ready=0

    if [ "$ready" -eq 1 ]; then
        ok "the panel answers on $url (version $running_version)"
        if [ "$NEW_VERSION" != unknown ] && [ "$running_version" != "$NEW_VERSION" ]; then
            warn "it reports $running_version but $REF is $NEW_VERSION"
            warn "  usually a second unit still running the old code: systemctl list-units 'tunnelgate*'"
        fi
    else
        printf 'the panel did not answer on %s within 20s:\n' "$url" >&2
        journalctl -u "$SERVICE" -n 30 --no-pager >&2 2>/dev/null || true
        if [ "$SWAPPED" -eq 1 ] && [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/code.tar.gz" ]; then
            warn "rolling back to $OLD_VERSION"
            tar -xzf "$BACKUP_DIR/code.tar.gz" -C "$INSTALL_DIR" 2>/dev/null || true
            if [ "$CODE_MODE" = git ] && [ -n "$OLD_REV" ]; then
                git_install checkout --quiet "$OLD_REV" 2>/dev/null || true
            fi
            if [ -f "$BACKUP_DIR/pip-freeze.txt" ]; then
                "$INSTALL_DIR/.venv/bin/pip" install --quiet --disable-pip-version-check \
                    -r "$BACKUP_DIR/pip-freeze.txt" >/dev/null 2>&1 || true
            fi
            chown -R "$RUN_USER:$RUN_GROUP" "$INSTALL_DIR" 2>/dev/null || true
            # A rollback that HAS worked must never be reported as a failure: the
            # operator's next move is completely different in the two cases.
            if restart_panel; then
                if rollback_version=$(wait_for_health "$url" 30); then
                    die "the new version did not start; $OLD_VERSION is running again (version $rollback_version).
       Service is restored, so nothing further is needed for that. The failed
       release is diagnosed above and its backup is in $BACKUP_DIR:
         journalctl -u $SERVICE -n 100 --no-pager"
                fi
            fi
            die "the new version did not start AND the rollback did not restore service.
       The backup is in $BACKUP_DIR. Look at:
         journalctl -u $SERVICE -n 200 --no-pager"
        fi
        die "the panel did not start. Look at: journalctl -u $SERVICE -n 50 --no-pager"
    fi
fi

# ------------------------------------------------------------------ 9. notes
# An update deliberately does NOT reinstall the unit: an operator may have edited
# it, and silently restoring the shipped one is how a hardened host becomes an
# unhardened one. Say that it differs instead, with the diff command.
if [ "$DRY_RUN" -eq 0 ] && [ -n "$UNIT_FILE" ] && [ -f "$INSTALL_DIR/deploy/systemd/$SERVICE.service" ]; then
    shipped=$(sed -n 's/^ExecStart=//p' "$INSTALL_DIR/deploy/systemd/$SERVICE.service" 2>/dev/null | head -n1)
    live=$(sed -n 's/^ExecStart=//p' "$UNIT_FILE" 2>/dev/null | head -n1)
    if [ -n "$shipped" ] && [ -n "$live" ] && [ "$shipped" != "$live" ]; then
        warn "the unit file shipped with $REF differs from the one in use:"
        warn "  in use:  $live"
        warn "  shipped: $shipped"
        warn "  diff $INSTALL_DIR/deploy/systemd/$SERVICE.service $UNIT_FILE"
        warn "  installing it was left to you: this script does not overwrite your unit"
    fi
fi

# ------------------------------------------------------------------ 10. doctor
say "running doctor"
if [ "$DRY_RUN" -eq 1 ]; then
    printf '  [dry-run] (as %s) app.cli doctor\n' "$RUN_USER"
else
    doctor_out=$(cd "$INSTALL_DIR" && as_panel "$VENV_PY" -m app.cli doctor 2>&1) || true
    printf '%s\n' "$doctor_out" | sed -e 's/^/     /'
    case "$doctor_out" in
        *FAIL*) warn "doctor reported a failing check: read it above. The update itself is done." ;;
    esac
fi

# ------------------------------------------------------------------ summary
FINAL_VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$INSTALL_DIR/app/__init__.py" 2>/dev/null | head -n1)
cat <<SUMMARY

$SERVICE is updated.

  version      $OLD_VERSION -> ${FINAL_VERSION:-unknown}
  ref          $REF
  code         $INSTALL_DIR
  backup       ${BACKUP_DIR:-<none>}
  logs         journalctl -u $SERVICE -f

  Live tunnels were not touched: the forwards are owned by sshd, not by the panel,
  so LuCI keeps working across the restart. Routers reconnect by themselves.

  If something is wrong, the way back is:
    tar -xzf ${BACKUP_DIR:-<none>}/code.tar.gz -C $INSTALL_DIR
    systemctl restart $SERVICE

SUMMARY
