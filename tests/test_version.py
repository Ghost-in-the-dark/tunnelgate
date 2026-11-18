"""One version string, in four files, quoted correctly by the documents.

The panel's version lives in four places that nothing joined together: `app/__init__.py` (what
`/api/v1/health` and `tunnelgate --version` report), `pyproject.toml` (what packaging tools
read), and `web/package.json` plus `web/package-lock.json` (what `npm` records). A release that
bumps three of them ships a panel whose health endpoint and whose lockfile disagree, and no test
would notice.

The documents are worse, because they are the only place an operator copies a command from. v1.0.0
told operators to fetch `scripts/quick-install.sh` from its own tag, where the file did not exist:
the documented install command returned 404 for the entire life of the release. Nothing asserted
that a documented command names a version that the repository actually publishes, so these checks
compare every pinned tag in the docs with the version in the tree.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "CHANGELOG.md"
README = REPO / "README.md"
DOCS = REPO / "docs"

SEMVER = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")

# Every way the documents pin a release. `--ref` is both installers' and the updater's flag;
# the raw.githubusercontent URL and the git checkout in the manual upgrade name the tag directly.
PINNED_REF = re.compile(r"--ref\s+v(?P<tag>\d+\.\d+\.\d+)")
PINNED_URL = re.compile(r"/v(?P<tag>\d+\.\d+\.\d+)/scripts/")
PINNED_CHECKOUT = re.compile(r"checkout\s+v(?P<tag>\d+\.\d+\.\d+)")


def _app_version() -> str:
    text = (REPO / "app" / "__init__.py").read_text()
    match = re.search(r'^__version__\s*=\s*"(?P<version>[^"]+)"', text, re.MULTILINE)
    assert match, "app/__init__.py has no __version__"
    return match.group("version")


def _pyproject_version() -> str:
    with (REPO / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def _package_version() -> str:
    return json.loads((REPO / "web" / "package.json").read_text())["version"]


def _lockfile_versions() -> set[str]:
    lock = json.loads((REPO / "web" / "package-lock.json").read_text())
    versions = {lock["version"]}
    root = lock.get("packages", {}).get("")
    if root is not None:
        versions.add(root["version"])
    return versions


def _documented_pins() -> list[tuple[str, str, int]]:
    """Every (file, tag, line number) a document pins, so a failure names the line to fix."""
    document = README.read_text()
    files = [(README.name, document)] + [
        (str(path.relative_to(REPO)), path.read_text()) for path in sorted(DOCS.glob("*.md"))
    ]
    pins: list[tuple[str, str, int]] = []
    for name, text in files:
        for pattern in (PINNED_REF, PINNED_URL, PINNED_CHECKOUT):
            for match in pattern.finditer(text):
                line = text[: match.start()].count("\n") + 1
                pins.append((name, match.group("tag"), line))
    return pins


def _changelog_sections() -> list[tuple[str, str, int]]:
    """(version, date, line) for every released section, newest first as written."""
    text = CHANGELOG.read_text()
    heading = re.compile(
        r"^## \[(?P<version>[^\]]+)\]\s+-\s+(?P<date>\d{4}-\d{2}-\d{2})\s*$", re.MULTILINE
    )
    return [
        (
            match.group("version"),
            match.group("date"),
            text[: match.start()].count("\n") + 1,
        )
        for match in heading.finditer(text)
    ]


# --------------------------------------------------------------------------- the four strings
def test_the_four_version_strings_agree() -> None:
    version = _app_version()
    assert SEMVER.match(version), f"app/__init__.py version is not semver: {version!r}"
    assert _pyproject_version() == version, "pyproject.toml disagrees with app/__init__.py"
    assert _package_version() == version, "web/package.json disagrees with app/__init__.py"
    assert _lockfile_versions() == {version}, (
        "web/package-lock.json disagrees with app/__init__.py: "
        + ", ".join(sorted(_lockfile_versions()))
    )


def test_the_router_installer_is_versioned_separately() -> None:
    """agent/install.sh carries the *client* protocol version, not the panel's.

    Its CLIENT_VERSION is what the panel records per router and what the installer compares
    against; tying it to the panel version would mean a panel patch release demands a router
    reinstall for nothing.
    """
    installer = (REPO / "agent" / "install.sh").read_text()
    match = re.search(r'^CLIENT_VERSION="(?P<version>[^"]+)"', installer, re.MULTILINE)
    assert match, "agent/install.sh has no CLIENT_VERSION"
    assert match.group("version").count(".") != 2, (
        "the client protocol version should not track the panel's semver"
    )


# --------------------------------------------------------------------------- the changelog
def test_changelog_opens_with_the_current_version() -> None:
    sections = _changelog_sections()
    assert sections, "CHANGELOG.md has no '## [x.y.z] - YYYY-MM-DD' section"
    version, date, line = sections[0]
    assert version == _app_version(), (
        f"CHANGELOG.md:{line} documents {version}, the code is {_app_version()}"
    )
    assert date, f"CHANGELOG.md:{line} has no release date"


def test_changelog_has_no_unreleased_placeholder() -> None:
    """A placeholder would let a release happen with nothing written down."""
    assert "## [Unreleased]" not in CHANGELOG.read_text()


def test_every_released_version_appears_in_the_tag_order() -> None:
    versions = [version for version, _date, _line in _changelog_sections()]
    assert len(set(versions)) == len(versions), f"duplicate changelog section: {versions}"
    keys = [tuple(int(part) for part in SEMVER.match(v).groups()) for v in versions]
    assert keys == sorted(keys, reverse=True), f"changelog sections are out of order: {versions}"


# --------------------------------------------------------------------------- the documents
def test_documents_pin_the_version_this_tree_carries() -> None:
    version = _app_version()
    pins = _documented_pins()
    assert pins, "no document pins a release at all - did the install docs lose their example?"
    wrong = [f"{name}:{line} pins v{tag}" for name, tag, line in pins if tag != version]
    assert not wrong, (
        "documents pin a version the tree does not carry (1.0.0 shipped a 404 install command "
        "this way): " + "; ".join(wrong)
    )


def test_the_install_documents_pin_a_version_at_all() -> None:
    """Dropping the pin entirely is also a regression: it installs whatever main happens to be."""
    install = (DOCS / "INSTALL_SERVER.md").read_text()
    assert PINNED_URL.search(install), "docs/INSTALL_SERVER.md no longer pins a tag in its URL"
    assert PINNED_REF.search(install), "docs/INSTALL_SERVER.md no longer pins a --ref"


def test_every_script_the_documents_pipe_is_published_at_that_tag() -> None:
    """The 1.0.0 defect: a documented URL naming a file the tag does not contain.

    `git ls-tree` needs a checkout; without one (a source tarball, an sdist) this is the best
    available check, so it asserts the file exists in the tree the tag will be cut from.
    """
    for name in ("scripts/quick-install.sh", "scripts/update.sh"):
        assert (REPO / name).is_file(), f"{name} is piped by the docs but missing from the tree"
    for document in (README, DOCS / "INSTALL_SERVER.md"):
        text = document.read_text()
        for match in re.finditer(r"tunnelgate/(?:main|v\d+\.\d+\.\d+)(/scripts/[\w.-]+\.sh)", text):
            relative = match.group(1).lstrip("/")
            assert (REPO / relative).is_file(), (
                f"{document.name} pipes {relative}, which is not in the tree"
            )
