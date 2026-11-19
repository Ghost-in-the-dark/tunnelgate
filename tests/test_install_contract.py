"""The rendered installer, executed the way a router executes it.

The panel never serves the raw `agent/install.sh`: app/services/bootstrap.py::render_install_script
prepends an injected header (a marker, the URL/token/os/tls assignments, a marker, a blank line)
before the body. So the file a router actually runs is the rendered one, and any check inside the
installer that inspects its own head has to survive that header.

That distinction is not academic. A `check_self()` guard that read only `head -n 2 "$0"` looked
correct against the raw file and rejected EVERY real install on every OpenWrt generation, because
the sentinel sits on line 8 of the rendered file. The tests in tests/test_installer.py read the raw
script, so none of them could see it.

These tests therefore render through the real service and run the result. They assert on WHICH
error came out, because that is the only thing that distinguishes "the guard let the script
through" from "the guard ate it".
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from app.config import Settings as _Settings
from app.services import bootstrap as bootstrap_service

NOT_THE_INSTALLER = "does not look like the TunnelGate installer"
NOT_OPENWRT = "does not look like OpenWrt"


def _render(body: str | None = None, token: str = "test-token-not-real") -> str:
    """The exact bytes the panel serves for a GET /api/v1/routers/install.

    `body` overrides the installer source, so a deliberately damaged script can be rendered
    through the same header the panel would prepend. Without that override the header is not
    under test at all.

    The override patches load_install_script rather than concatenating a header by hand: the
    renderer splices its block in after the body's first two lines (shebang, identifier), and a
    hand-assembled header would model that splice differently from the code under test - which is
    exactly the mistake that let the original ordering bug through.
    """
    settings = _Settings(panel_url="https://panel.example.com")
    if body is None:
        return bootstrap_service.render_install_script(token, "linux", settings)
    original = bootstrap_service.load_install_script
    bootstrap_service.load_install_script = lambda: body
    try:
        return bootstrap_service.render_install_script(token, "linux", settings)
    finally:
        bootstrap_service.load_install_script = original


def _rendered_header(token: str = "test-token-not-real") -> str:
    """Just the header the panel splices in, as bytes.

    The renderer keeps the body's shebang and identifier comment as lines 1-2 and inserts its own
    block between them and the rest, so the header is neither a prefix nor a suffix of the served
    file - it is the span between the two.
    """
    body = bootstrap_service.load_install_script()
    rendered = _render(token=token)
    shebang, identifier, rest = body.split(chr(10), 2)
    prefix = f"{shebang}{chr(10)}{identifier}{chr(10)}"
    assert rendered.startswith(prefix), "the served script does not start with the body's shebang"
    assert rendered.endswith(rest), "the served script does not end with the body after line 2"
    return rendered[len(prefix) : len(rendered) - len(rest)]


def _run(script: str, tmp_path) -> subprocess.CompletedProcess:
    """Write the body to a file and execute it the way the install command does: sh <file>."""
    shell = shutil.which("sh")
    assert shell, "no /bin/sh to execute the installer with"
    path = tmp_path / "tg-install.sh"
    path.write_text(script, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("TG_")}
    return subprocess.run(
        [shell, str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        cwd=str(tmp_path),
    )


def test_the_panel_does_prepend_the_header_the_installer_has_to_survive() -> None:
    """Pin the shape the installer is allowed to assume.

    If the renderer gains another assignment (it gained TG_TLS_VERIFY for the self-signed-panel
    feature, which is exactly how a two-line window was missed) this test does not fail - but it
    makes the reason obvious to the next reader.
    """
    rendered = _render()
    header = _rendered_header()
    assert header.strip(), (
        "the renderer prepended nothing: check_self would be testing the raw file"
    )
    assert header.count(chr(10)) >= 6, repr(header)
    assert "TG_PANEL_URL=" in header
    assert "TG_BOOTSTRAP_TOKEN=" in header
    sentinel_lines = [
        index
        for index, line in enumerate(rendered.splitlines(), start=1)
        if bootstrap_service.INSTALL_SENTINEL in line
    ]
    assert sentinel_lines, "the rendered script lost the install command's sentinel"
    assert sentinel_lines[0] > 1, (
        "the sentinel is on line 1, so these tests are not exercising the injected header"
    )


@pytest.mark.skipif(os.geteuid() != 0, reason="the installer refuses to run as non-root")
def test_the_rendered_installer_gets_past_its_own_self_check(tmp_path) -> None:
    """The regression: a two-line self-check silently rejected every real install.

    Run outside OpenWrt the installer must stop at the OpenWrt check. If it stops at the
    self-check instead, the guard is reading too little of the file and no operator can install.
    """
    result = _run(_render(), tmp_path)
    output = result.stdout + result.stderr
    assert NOT_THE_INSTALLER not in output, (
        "the installer rejected the panel's own render as not-the-installer: a guard inside the"
        " script is inspecting too small a window of its own head." + chr(10) + output
    )
    assert NOT_OPENWRT in output, (
        "expected the OpenWrt check to stop a run on this host; got:" + chr(10) + output
    )


@pytest.mark.skipif(os.geteuid() != 0, reason="the installer refuses to run as non-root")
def test_a_shell_valid_body_without_the_sentinel_is_still_rejected(tmp_path) -> None:
    """The guard has to keep doing its job: widening the window must not weaken it.

    An HTML body is not the interesting case: the shell rejects it at the parser, before any
    check inside the script runs - which is why the panel-side grep exists in the first place.
    The case this guard covers is a body that IS valid shell and WOULD run: a captive portal that
    answers with a script, a truncated download, a proxy error page that happens to parse. So the
    fixture is the real installer with only its sentinel line rewritten: everything else is
    byte-identical, the script parses, main() is reached - and the self-check is the only thing
    between this body and an install attempt.
    """
    body = bootstrap_service.load_install_script()
    # Scrub only the HEAD, which is all check_self looks at. Scrubbing the whole file would also
    # rewrite the guard's own grep literal, and the guard would then find the replacement string
    # in its own source and pass - a fixture that proves nothing.
    lines = body.splitlines(keepends=True)
    head = 40
    scrubbed = [
        line.replace(bootstrap_service.INSTALL_SENTINEL, "Some Other Project installer")
        if index < head
        else line
        for index, line in enumerate(lines)
    ]
    impostor = "".join(scrubbed)
    assert impostor != body, "the shipped installer no longer carries the sentinel in its head"
    shell = shutil.which("sh")
    parsed = subprocess.run(
        [shell, "-n"], input=impostor, capture_output=True, text=True, timeout=60
    )
    assert parsed.returncode == 0, "the fixture is not valid shell: " + parsed.stderr

    result = _run(_render(impostor), tmp_path)
    output = result.stdout + result.stderr
    assert NOT_THE_INSTALLER in output, (
        "a shell-valid body with no sentinel got past the self-check:" + chr(10) + output
    )


def test_the_served_script_is_executable_as_a_file_not_just_through_sh() -> None:
    """A served script must be runnable directly: the shebang has to be the first line.

    This is the quieter half of the same bug. When the panel prepended its header, line 1 became
    a comment and the shebang moved to line 7. Nothing failed loudly: `sh -n` passes on such a
    file, and the documented command runs it as `sh "$F"`, which also passes. But an operator who
    runs the downloaded file directly gets it interpreted by whatever shell happens to be
    current - on a router, possibly not the one the script was written for - and every check
    inside it that reads its own head sees the header instead of what it expected.

    So pin the two things that make the file self-describing: the shebang is line 1, and the
    sentinel line follows it before any injected assignment.
    """
    lines = _render().splitlines()
    assert lines[0] == "#!/bin/sh", "line 1 of the served script must be the shebang; got " + repr(
        lines[0]
    )
    assert bootstrap_service.INSTALL_SENTINEL in lines[1], (
        "the installer sentinel must follow the shebang, before the panel preamble; got "
        + repr(lines[1])
    )
    preamble = [index for index, line in enumerate(lines) if line.startswith("TG_PANEL_URL=")]
    assert preamble, "the panel preamble is missing from the served script"
    assert preamble[0] > 1, "the injected preamble is above the shebang/sentinel: " + repr(
        lines[:4]
    )


@pytest.mark.skipif(os.geteuid() != 0, reason="the installer refuses to run as non-root")
def test_the_served_script_runs_when_invoked_directly(tmp_path) -> None:
    # Execute the served file as a FILE (chmod +x, no explicit interpreter). The kernel reads
    # the shebang; if there is none it either refuses with Exec format error or hands the file
    # to the caller's shell - both silent failures for an operator. On this non-OpenWrt host the
    # expected outcome is the OpenWrt check; what matters is that execution gets that far.
    path = tmp_path / "tg-install.sh"
    path.write_text(_render(), encoding="utf-8")
    path.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith("TG_")}
    result = subprocess.run(
        [str(path)], capture_output=True, text=True, timeout=60, env=env, cwd=str(tmp_path)
    )
    output = result.stdout + result.stderr
    assert "Exec format error" not in output, "the served script has no usable shebang: " + output
    assert NOT_OPENWRT in output, (
        "running the served file directly did not reach the OpenWrt check: " + output
    )
