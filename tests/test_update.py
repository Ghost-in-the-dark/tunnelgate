"""Guards for scripts/update.sh.

The updater is the one script that runs as root against a host that is already
serving traffic, so every interesting decision in it is a claim about safety:
the backup happens before any mutation, the live database is never written
before the new code has proved it can start, a release that needs hand work
stops the update instead of half-applying it, and a rollback that worked must
not report itself as a failure. Each of those was a real bug found by running
the script against a live instance, so they are pinned here rather than left to
review.
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UPDATE_SH = REPO / "scripts" / "update.sh"
INSTALL_DOC = REPO / "docs" / "INSTALL_SERVER.md"
OPERATIONS_DOC = REPO / "docs" / "OPERATIONS.md"
README = REPO / "README.md"

DOLLAR = chr(36)
EXPAND = DOLLAR + chr(123)


def _text() -> str:
    return UPDATE_SH.read_text()


def _directives(text: str) -> list[str]:
    """Lines that actually execute, so comments may discuss a forbidden thing."""
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def _index_of(text: str, needle: str) -> int:
    position = text.find(needle)
    assert position != -1, f"the updater no longer contains {needle!r}"
    return position


def test_update_script_is_executable_and_parses() -> None:
    assert UPDATE_SH.exists(), "scripts/update.sh is missing"
    assert UPDATE_SH.stat().st_mode & stat.S_IXUSR, "update.sh must be executable"
    result = subprocess.run(
        ["sh", "-n", str(UPDATE_SH)], capture_output=True, text=True, check=False, cwd=REPO
    )
    assert result.returncode == 0, result.stderr
    busybox = subprocess.run(
        ["busybox", "sh", "-n", str(UPDATE_SH)],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
    )
    if busybox.returncode != 127:  # busybox is optional on a dev box; CI has it
        assert busybox.returncode == 0, busybox.stderr


def test_update_script_is_posix_and_aborts_on_error() -> None:
    text = _text()
    assert text.startswith("#!/bin/sh"), "the updater must stay POSIX sh for a minimal host"
    assert "set -eu" in text, "an unset variable must abort, not silently expand to empty"
    # bash-only constructs would fail on dash/busybox, which is what a minimal VPS
    # or a router-adjacent jump host actually has. Note that the arithmetic
    # expansion "$((" is POSIX, so only a bare "((" command is a bashism.
    for bashism in ("[[ ", "function ", "pipefail", EXPAND + "!", "\n((", "if (("):
        assert bashism not in text, f"{bashism!r} is not POSIX sh"
    for line in _directives(text):
        assert not re.match(r"\s*local\s", line), f"bash 'local' keyword: {line!r}"


def test_backup_happens_before_the_first_mutation() -> None:
    """A backup taken after the first write records the damage instead of preventing it."""
    text = _text()
    backup = _index_of(text, "backing up")
    for mutation in (
        "installing the Python dependencies",
        "checking the database schema",
        "installing the new code",
        "rsync -a --delete",
    ):
        assert backup < _index_of(text, mutation), f"{mutation!r} runs before the backup"


def test_the_live_database_is_never_checked_in_place() -> None:
    """check-schema calls init-db, which CREATES tables: on the live file that is a write."""
    text = _text()
    assert "TUNNELGATE_DB_URL=sqlite:///" + DOLLAR + "SCHEMA_DB" in text, (
        "the schema check must point at a snapshot of the database"
    )
    assert "TUNNELGATE_DATA_DIR=" + DOLLAR + "SCHEMA_TMP" in text, (
        "the check also needs its own data dir, or init-db writes beside production"
    )
    # The snapshot is taken with .backup (a copied -wal is not a consistent database)
    # and it is handed to the service account, which is who runs the check.
    assert ".backup" in text
    assert (
        'chown -R "' + DOLLAR + "RUN_USER:" + DOLLAR + 'RUN_GROUP" "' + DOLLAR + 'SCHEMA_TMP"'
    ) in text, "mktemp -d is 0700 root; the service account cannot open an un-handed-over snapshot"


def test_a_release_that_needs_hand_work_stops_the_update() -> None:
    text = _text()
    assert "--skip-schema-check" in text, "there must be a documented way past a known-good check"
    assert "ALTER TABLE" in text, "the operator needs the statements, not just a refusal"
    stop = _index_of(text, "the database schema needs hand work first")
    assert stop < _index_of(text, "rsync -a --delete"), "the refusal must precede the swap"


def test_a_failed_check_is_not_reported_as_schema_drift() -> None:
    """A probe that could not run must not tell the operator to write ALTER TABLEs."""
    text = _text()
    assert "the schema check could not run" in text, (
        "distinguish 'the release needs migrations' from 'the check itself broke'"
    )


def test_restart_not_reload_and_a_rollback_that_worked_says_so() -> None:
    text = _text()
    assert "systemctl restart" in text
    assert "systemctl reload" not in text, (
        "uvicorn keeps already-imported modules across a reload: the old code would "
        "keep serving behind a new version number"
    )
    assert "is running again" in text, "a successful rollback must say service is restored"
    assert text.count("wait_for_health") >= 3, (
        "the health wait must be shared by the update path and the rollback path"
    )


def test_the_unit_file_is_never_silently_restored() -> None:
    """An operator may have hardened the unit; a shipped copy must not undo that."""
    text = _text()
    for forbidden in ("install -m 0644 deploy/systemd", "cp deploy/systemd", "cp -f"):
        assert forbidden not in text
    assert "deploy/systemd/" + DOLLAR + "SERVICE.service" in text
    assert "diff " in text, "it must offer the diff instead of overwriting"


def test_cleanup_only_removes_paths_the_script_created() -> None:
    """A bad variable must never become an rm -rf of the install directory."""
    text = _text()
    start = text.index("cleanup() {")
    cleanup = text[start : text.index("trap cleanup EXIT")]
    removals = [line.strip() for line in cleanup.splitlines() if "rm -rf" in line]
    assert removals, "cleanup still removes something"
    for line in removals:
        assert (
            "tunnelgate-update-src." in line
            or ".update-staging" in line
            or "tunnelgate-update-probe." in line
        ), f"unguarded cleanup: {line!r}"
    assert "case " in cleanup, "cleanup must gate each removal on a path pattern"


def test_an_update_from_a_dirty_checkout_is_refused() -> None:
    text = _text()
    assert "An update that silently discards local edits is not an update." in text
    # The staging tree lives inside the install dir, so the dirty check must exclude
    # it or every git-mode update refuses itself.
    assert ":(exclude).update-staging" in text, (
        "the staging dir would fail the dirty check that guards the same tree"
    )


def test_git_operations_survive_root_acting_on_a_service_owned_tree() -> None:
    """Production ownership makes bare git die with 'dubious ownership'."""
    text = _text()
    for line in _directives(text):
        if "git -C" in line and "git_install" not in line:
            raise AssertionError(f"bare 'git -C' ignores safe.directory: {line!r}")
    assert 'git -c "safe.directory=' + DOLLAR + 'INSTALL_DIR"' in text
    assert "git config --global" not in text, (
        "the updater must not rewrite the host's global git config"
    )


def test_prompts_never_read_the_script_from_stdin() -> None:
    """The supported invocation pipes this file into sh; stdin is the program."""
    text = _text()
    assert "curl -fsSL" in text
    reads = [
        line.strip() for line in _directives(text) if re.match(r"\s*(IFS=[^ ]* )?read\b", line)
    ]
    assert reads, "the confirmation prompt is gone"
    for line in reads:
        assert "</dev/tty" in line, f"a prompt reads stdin: {line!r}"
    assert "have_tty()" in text
    assert "[ -t 1 ]" in text, "prompting into a redirected log must not happen"


def test_downloaded_and_staged_trees_are_handed_to_the_service_account() -> None:
    """mktemp -d and a root-owned stage both break a check that runs as the panel."""
    text = _text()
    needle = 'chown -R "' + DOLLAR + "RUN_USER:" + DOLLAR + 'RUN_GROUP"'
    assert text.count(needle) >= 4, (
        "the schema snapshot, the downloaded tree, the stage and the install dir all "
        "need to be readable/writable by the service account"
    )


def test_the_health_check_asks_the_panel_which_version_it_runs() -> None:
    text = _text()
    assert "/api/v1/health" in text
    assert "systemctl is-active" not in text, (
        "a unit whose process dies on its first bind is briefly ACTIVE and then in "
        "auto-restart, so systemd's own verdict is not proof of health"
    )


def test_check_only_touches_nothing() -> None:
    text = _text()
    assert "--check-only" in text and "--dry-run" in text
    check_only = _index_of(text, "Nothing was changed (--check-only)")
    assert check_only < _index_of(text, "backing up"), (
        "--check-only must report and exit before the backup, i.e. before any write"
    )


def test_bad_arguments_exit_two() -> None:
    """A caller scripting this needs 'you asked something impossible' != 'I stopped safely'."""
    result = subprocess.run(
        ["sh", str(UPDATE_SH), "--nonsense"], capture_output=True, text=True, check=False, cwd=REPO
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert "unknown argument" in (result.stdout + result.stderr)
    for bad in (["--ref", "bad ref!"], ["--install-dir", "relative/path"]):
        result = subprocess.run(
            ["sh", str(UPDATE_SH), *bad], capture_output=True, text=True, check=False, cwd=REPO
        )
        assert result.returncode == 2, f"{bad} -> {result.returncode}"


def test_help_documents_the_refusals_and_the_rollback() -> None:
    result = subprocess.run(
        ["sh", str(UPDATE_SH), "--help"], capture_output=True, text=True, check=False, cwd=REPO
    )
    assert result.returncode == 0
    help_text = result.stdout
    for expected in ("--check-only", "--skip-schema-check", "--ref", "EXIT CODES", "ROLLBACK"):
        assert expected in help_text, f"--help no longer documents {expected}"


def test_docs_point_at_the_update_script() -> None:
    for name, path in (("INSTALL_SERVER.md", INSTALL_DOC), ("OPERATIONS.md", OPERATIONS_DOC)):
        assert "scripts/update.sh" in path.read_text(), f"{name} must document the updater"
    assert "scripts/update.sh" in README.read_text()
