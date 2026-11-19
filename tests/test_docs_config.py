"""The documentation's claims about app/config.py, checked instead of trusted.

Two docs describe the environment surface:

* docs/CONFIGURATION.md says the Settings class has 61 fields and that "the count is checked by
  the tests"
* deploy/env/tunnelgate.env.example says it "stays the complete inventory of the 61 settings (it
  is checked against app/config.py)"

Before this file neither sentence was true. A settings count in prose rots on the first field
anyone adds, and an env example silently stops being an inventory the first time a setting is
renamed - so the claims are made executable here rather than deleted, because the numbers
themselves are useful to a reader.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.config import Settings

REPO = Path(__file__).resolve().parent.parent
CONFIGURATION = REPO / "docs" / "CONFIGURATION.md"
INSTALL_SERVER = REPO / "docs" / "INSTALL_SERVER.md"
INDEX = REPO / "docs" / "INDEX.md"
ENV_EXAMPLE = REPO / "deploy" / "env" / "tunnelgate.env.example"

# TUNNELGATE_ENV_FILE is read by pydantic, not defined by Settings, so it is not a field.
_NOT_A_FIELD = {"TUNNELGATE_ENV_FILE"}


def _field_count() -> int:
    return len(Settings.model_fields)


def _documented_count(path: Path) -> int:
    """The number the document claims, e.g. "defines 61 settings" or "with 61 fields"."""
    text = path.read_text(encoding="utf-8")
    match = re.search(r"\b(\d+)\s+(?:settings|fields)", text)
    assert match, f"{path.name} no longer states how many settings there are"
    return int(match.group(1))


def test_the_documented_setting_counts_match_the_code():
    count = _field_count()
    assert _documented_count(CONFIGURATION) == count
    assert _documented_count(INSTALL_SERVER) == count


def test_the_index_agrees_with_the_reference():
    """INDEX.md quotes the count too, so a bump has to move three files, not one."""
    text = INDEX.read_text(encoding="utf-8")
    assert f"defines {_field_count()}" in text


def test_the_env_example_is_the_whole_inventory():
    """Every Settings field is at least named in the example, and nothing invented is."""
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    mentioned = set(re.findall(r"TUNNELGATE_[A-Z0-9_]+", text))
    expected = {f"TUNNELGATE_{name.upper()}" for name in Settings.model_fields}
    missing = expected - mentioned
    assert not missing, f"deploy/env/tunnelgate.env.example never mentions {sorted(missing)}"
    # TUNNELGATE_PORT is deliberately named there and is not a field: the docs call it out.
    unexpected = mentioned - expected - _NOT_A_FIELD - {"TUNNELGATE_PORT"}
    assert not unexpected, f"the example documents settings that do not exist: {sorted(unexpected)}"


def test_the_port_variable_is_explained_because_it_is_not_a_setting():
    """The one variable in the example that Settings does not read has to be called out."""
    text = INSTALL_SERVER.read_text(encoding="utf-8")
    assert "is **not** a setting" in text


def test_the_docs_directory_index_lists_every_document():
    """docs/INDEX.md claims to be the map: a document it forgets is a document nobody finds."""
    index = INDEX.read_text(encoding="utf-8")
    missing = [
        path.name
        for path in sorted((REPO / "docs").glob("*.md"))
        if path.name != "INDEX.md" and path.name not in index
    ]
    assert not missing, f"docs/INDEX.md does not link {missing}"


# --------------------------------------------------------------------------- install-command docs
# The install command is the one artefact an operator copies by hand, and it existed in a shape
# that could not work on a stock router for months: no OpenWrt image ships curl. Prose copies rot
# faster than code, so the shape is pinned here rather than trusted.

# What a doc must NOT tell an operator to run: curl with a token header. Both halves are
# impossible on a stock image (no curl; uclient-fetch had no --header before 24.10).
_FORBIDDEN_INSTALL_PATTERNS = (
    "curl -fsSL -H 'X-Bootstrap-Token",
    'curl -sS -H "X-Bootstrap-Token',
    'curl -fsSL -H "X-Bootstrap-Token',
)

# Any document that shows the install URL therefore has to show the fetcher probe as well.
_PROBE_MARKER = "command -v curl"


def _command_documents() -> list[Path]:
    """Every markdown file in the repository that quotes the install endpoint."""
    return [
        path
        for path in sorted(REPO.rglob("*.md"))
        if ".venv" not in path.parts
        and "node_modules" not in path.parts
        and "api/v1/routers/install?os=linux" in path.read_text(encoding="utf-8")
    ]


def test_the_command_documents_are_not_empty():
    """Guard the guard: a path change must not make the scans below vacuous."""
    assert _command_documents(), "no document quotes the install endpoint any more"


def test_no_document_shows_a_curl_only_install_command():
    """The curl-with-a-header one-liner cannot run on a stock OpenWrt and must not be taught."""
    offenders = []
    for path in _command_documents():
        text = path.read_text(encoding="utf-8")
        for pattern in _FORBIDDEN_INSTALL_PATTERNS:
            if pattern in text:
                offenders.append(f"{path.relative_to(REPO)} contains {pattern!r}")
    assert not offenders, "\n".join(offenders)


def test_every_document_that_shows_the_command_also_shows_the_fetcher_probe():
    """The command has to branch on what the router actually has, not assume curl."""
    offenders = [
        str(path.relative_to(REPO))
        for path in _command_documents()
        if _PROBE_MARKER not in path.read_text(encoding="utf-8")
    ]
    assert not offenders, (
        "these documents show the install endpoint without the fetcher probe: "
        + ", ".join(offenders)
    )
