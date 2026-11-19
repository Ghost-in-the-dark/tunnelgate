"""The agent-facing endpoint: what routers are told to dial, and how it can be changed.

It is separate from TUNNELGATE_PANEL_URL because the panel's own address (the internal one a
reverse proxy forwards to) and the address a router on a customer network dials are allowed to
differ - and because an operator who moves the panel must be able to re-point the install
instructions without editing env files on the host.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.db import session_scope
from app.services import agent_endpoint


@pytest.fixture(autouse=True)
def _isolated_db(settings):
    """Every test here runs against its own temp database built by conftest.

    Without this the session_scope() calls below would hit whatever TUNNELGATE_DB_URL points
    at (the developer's dev database) instead of an isolated one.
    """
    return settings


def make_settings(**overrides) -> Settings:
    params = {
        "env": "test",
        "panel_url": "http://127.0.0.1:8080",
        "panel_host": "panel.test",
    }
    params.update(overrides)
    return Settings(**params)


# ------------------------------------------------------------------ rendering
@pytest.mark.parametrize(
    ("scheme", "host", "port", "expected"),
    [
        ("https", "panel.example.com", None, "https://panel.example.com"),
        ("https", "panel.example.com", 443, "https://panel.example.com"),
        ("http", "panel.example.com", 80, "http://panel.example.com"),
        ("https", "panel.example.com", 8443, "https://panel.example.com:8443"),
        ("http", "127.0.0.1", 8080, "http://127.0.0.1:8080"),
        ("https", "2001:db8::1", None, "https://[2001:db8::1]"),
        ("https", "2001:db8::1", 8443, "https://[2001:db8::1]:8443"),
    ],
)
def test_url_rendering(scheme, host, port, expected) -> None:
    endpoint, problems = agent_endpoint.normalize(scheme, host, port)
    assert problems == {}
    assert endpoint.url == expected


def test_the_default_port_is_normalised_away() -> None:
    endpoint, _ = agent_endpoint.normalize("https", "panel.test", 443)
    assert endpoint.port is None
    assert endpoint.effective_port == 443


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize(
    "host",
    [
        "panel.test/path",
        "https://panel.test",
        "user@panel.test",
        "panel.test:443",
        "panel test",
        "panel.test; rm -rf /",
        "panel.test'",
        "-panel.test",
        "panel..test",
        ".panel.test",
        "panel.test.",
        "a" * 254,
    ],
)
def test_bad_hosts_are_refused(host) -> None:
    endpoint, problems = agent_endpoint.normalize("https", host, None)
    assert endpoint is None
    assert "host" in problems


@pytest.mark.parametrize("scheme", ["ftp", "gopher", "", "HTTPS "])
def test_only_http_and_https_are_accepted(scheme) -> None:
    endpoint, problems = agent_endpoint.normalize(scheme, "panel.test", None)
    if scheme.strip().lower() == "https":
        assert problems == {}
        return
    assert endpoint is None
    assert "scheme" in problems


@pytest.mark.parametrize("port", [0, -1, 65536, 100000])
def test_bad_ports_are_refused(port) -> None:
    endpoint, problems = agent_endpoint.normalize("https", "panel.test", port)
    assert endpoint is None
    assert "port" in problems


def test_an_invalid_ipv4_literal_is_refused() -> None:
    endpoint, problems = agent_endpoint.normalize("https", "999.1.1.1", None)
    assert endpoint is None
    assert "host" in problems


def test_a_bracketed_ipv6_literal_is_unwrapped() -> None:
    endpoint, problems = agent_endpoint.normalize("https", "[2001:db8::5]", None)
    assert problems == {}
    assert endpoint.host == "2001:db8::5"


# ------------------------------------------------------------------ sourcing
def test_the_environment_is_the_fallback() -> None:
    endpoint = agent_endpoint.effective(None, make_settings(panel_url="https://panel.example.com"))
    assert endpoint.source == agent_endpoint.SOURCE_ENVIRONMENT
    assert endpoint.url == "https://panel.example.com"


def test_a_database_row_overrides_the_environment() -> None:
    with session_scope() as db:
        agent_endpoint.save(db, "https", "moved.example.com", 8443)
        db.commit()
        endpoint = agent_endpoint.effective(db, make_settings())
        assert endpoint.source == agent_endpoint.SOURCE_DATABASE
        assert endpoint.url == "https://moved.example.com:8443"
        assert agent_endpoint.agent_url(db, make_settings()) == "https://moved.example.com:8443"


def test_clearing_the_row_restores_the_environment() -> None:
    with session_scope() as db:
        agent_endpoint.save(db, "https", "moved.example.com", None)
        db.commit()
        assert agent_endpoint.clear(db) is True
        db.commit()
        endpoint = agent_endpoint.effective(db, make_settings())
        assert endpoint.source == agent_endpoint.SOURCE_ENVIRONMENT
        # Idempotent: nothing left to remove.
        assert agent_endpoint.clear(db) is False


def test_a_corrupt_row_is_ignored_rather_than_breaking_installs() -> None:
    from app.models import PanelSetting

    with session_scope() as db:
        db.add(PanelSetting(key=agent_endpoint.AGENT_ENDPOINT_KEY, value="{not json"))
        db.commit()
        endpoint = agent_endpoint.effective(db, make_settings(panel_url="https://panel.test"))
        assert endpoint.source == agent_endpoint.SOURCE_ENVIRONMENT


def test_a_row_that_would_render_a_broken_url_is_ignored() -> None:
    from app.models import PanelSetting

    with session_scope() as db:
        db.add(
            PanelSetting(
                key=agent_endpoint.AGENT_ENDPOINT_KEY,
                value='{"scheme": "https", "host": "bad host", "port": null}',
            )
        )
        db.commit()
        endpoint = agent_endpoint.effective(db, make_settings(panel_url="https://panel.test"))
        assert endpoint.url == "https://panel.test"


def test_from_panel_url_ignores_a_path() -> None:
    endpoint = agent_endpoint.from_panel_url("https://panel.test/tunnelgate/")
    assert endpoint.url == "https://panel.test"


def test_from_panel_url_refuses_a_non_http_url() -> None:
    assert agent_endpoint.from_panel_url("ftp://panel.test") is None
    assert agent_endpoint.from_panel_url("") is None


def test_agent_url_never_raises_on_a_broken_setting() -> None:
    """The installer must still render; the raw string is more useful than a 500."""
    assert agent_endpoint.agent_url(None, make_settings(panel_url="nonsense")) == "nonsense"


def test_save_reports_field_problems_and_writes_nothing() -> None:
    from app.models import PanelSetting

    with session_scope() as db:
        endpoint, problems = agent_endpoint.save(db, "https", "bad host", None)
        assert endpoint is None
        assert "host" in problems
        assert db.get(PanelSetting, agent_endpoint.AGENT_ENDPOINT_KEY) is None


# ------------------------------------------------------------------ probe
def test_probe_reports_an_unreachable_target_without_raising(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("httpx.get", boom)
    result = agent_endpoint.probe("https://panel.test")
    assert result["ok"] is False
    assert result["checked_url"] == "https://panel.test/api/v1/health"
    assert "connection refused" in result["error"]


def test_probe_rejects_a_200_that_is_not_a_panel(monkeypatch) -> None:
    class Response:
        status_code = 200

        def json(self):
            return {"hello": "world"}

    monkeypatch.setattr("httpx.get", lambda *a, **k: Response())
    result = agent_endpoint.probe("https://panel.test")
    assert result["ok"] is False
    assert result["status_code"] == 200
    assert "not a TunnelGate panel" in result["error"]


def test_probe_accepts_a_healthy_panel(monkeypatch) -> None:
    class Response:
        status_code = 200

        def json(self):
            return {"status": "ok", "version": "1.0.0"}

    monkeypatch.setattr("httpx.get", lambda *a, **k: Response())
    result = agent_endpoint.probe("https://panel.test/")
    assert result["ok"] is True
    assert result["checked_url"] == "https://panel.test/api/v1/health"
    assert result["latency_ms"] is not None


# --------------------------------------------------- a loopback panel_url is not a router's address
def test_a_loopback_panel_url_falls_back_to_the_public_origin() -> None:
    """The documented install shape: nginx on the panel host forwards to 127.0.0.1.

    A router on a customer network cannot dial 127.0.0.1, so the agent URL has to be the public
    origin the operator named - otherwise a fresh install hands out an install command that only
    works on the panel host itself.
    """
    settings = make_settings(
        panel_url="http://127.0.0.1:8080", public_url="https://panel.example.com"
    )
    endpoint = agent_endpoint.environment_endpoint(settings)
    assert endpoint.url == "https://panel.example.com"
    assert agent_endpoint.agent_url(None, settings) == "https://panel.example.com"


def test_a_public_panel_url_wins_over_the_public_origin() -> None:
    """A flat install (panel_url already public) keeps behaving exactly as before."""
    settings = make_settings(
        panel_url="https://direct.example.com", public_url="https://panel.example.com"
    )
    assert agent_endpoint.environment_endpoint(settings).url == "https://direct.example.com"


def test_the_public_fallback_keeps_a_non_default_port() -> None:
    settings = make_settings(
        panel_url="http://127.0.0.1:8080", public_url="http://panel.example.com:8095"
    )
    assert agent_endpoint.environment_endpoint(settings).url == "http://panel.example.com:8095"


def test_a_loopback_public_origin_is_not_an_improvement() -> None:
    """Nothing usable means the loopback value is still reported, so doctor can explain it."""
    settings = make_settings(panel_url="http://127.0.0.1:8080", public_url="http://127.0.0.1:8080")
    endpoint = agent_endpoint.environment_endpoint(settings)
    assert endpoint.host == "127.0.0.1"
    assert agent_endpoint.agent_url(None, settings) == "http://127.0.0.1:8080"


def test_a_stored_override_still_beats_the_public_fallback() -> None:
    with session_scope() as db:
        agent_endpoint.save(db, "https", "moved.example.com", None)
        db.commit()
        settings = make_settings(
            panel_url="http://127.0.0.1:8080", public_url="https://panel.example.com"
        )
        endpoint = agent_endpoint.effective(db, settings)
        assert endpoint.url == "https://moved.example.com"
        assert endpoint.source == agent_endpoint.SOURCE_DATABASE


# ------------------------------------------------------------------ TLS trust
def test_verify_tls_defaults_to_true_when_the_row_does_not_carry_it() -> None:
    """Rows written by 1.0.0/1.1.0 have no verify_tls; they must load as verifying.

    Backward compatibility matters here in one direction only: an old row that silently
    disabled certificate checks would be a downgrade nobody asked for.
    """
    from app.models import PanelSetting

    with session_scope() as db:
        db.add(
            PanelSetting(
                key=agent_endpoint.AGENT_ENDPOINT_KEY,
                value='{"scheme": "https", "host": "legacy.example.com", "port": null}',
            )
        )
        db.commit()
        endpoint = agent_endpoint.effective(db, make_settings())
        assert endpoint.source == agent_endpoint.SOURCE_DATABASE
        assert endpoint.verify_tls is True


def test_an_http_endpoint_always_reports_verification_on() -> None:
    """Normalisation, not validation: http has no certificate, so false would be a lie.

    The SPA renders this value, so returning false would show the operator a warning about an
    insecure connection when the connection is merely unencrypted. Erroring would also be
    wrong: nothing the operator asked for is impossible.
    """
    endpoint, problems = agent_endpoint.normalize("http", "panel.example.com", None, False)
    assert problems == {}
    assert endpoint.verify_tls is True


def test_an_https_endpoint_can_store_a_self_signed_acceptance() -> None:
    endpoint, problems = agent_endpoint.normalize("https", "panel.example.com", None, False)
    assert problems == {}
    assert endpoint.verify_tls is False
    # The URL is unchanged by the TLS policy: the address stays pasteable and loggable.
    assert endpoint.url == "https://panel.example.com"


def test_save_and_clear_round_trip_the_tls_policy() -> None:
    with session_scope() as db:
        endpoint, problems = agent_endpoint.save(
            db, "https", "self.example.com", None, verify_tls=False
        )
        assert problems == {}
        assert endpoint.verify_tls is False
        db.commit()
        reloaded = agent_endpoint.effective(db, make_settings())
        assert reloaded.source == agent_endpoint.SOURCE_DATABASE
        assert reloaded.verify_tls is False
        assert agent_endpoint.clear(db) is True
        db.commit()
        restored = agent_endpoint.effective(db, make_settings(panel_url="https://env.example.com"))
        assert restored.source == agent_endpoint.SOURCE_ENVIRONMENT
        # The env file has no TLS knob, so clearing the row returns the safe default.
        assert restored.verify_tls is True


def test_the_url_never_carries_the_tls_policy() -> None:
    """Live, the URL is generated independently of verify_tls.

    One test for one fact: the endpoint URL must stay a plain address whichever way the policy
    points, because it is pasted into a router and appears in logs.
    """
    fresh, _ = agent_endpoint.normalize("https", "panel.example.com", None, True)
    loose, _ = agent_endpoint.normalize("https", "panel.example.com", None, False)
    assert fresh.url == loose.url
    assert "insecure" not in loose.url
    assert "verify" not in loose.url


def test_an_unusable_stored_value_still_verifies() -> None:
    """Anything unrecognised falls back to verifying, never to skipping the check."""
    for value in (None, "banana", [], {}, 0.5):
        endpoint, problems = agent_endpoint.normalize("https", "panel.example.com", None, value)
        assert problems == {}
        assert endpoint.verify_tls is True, value


@pytest.mark.parametrize(("stored", "expected"), [("false", False), ("0", False), (False, False)])
def test_a_json_row_spelling_false_is_honoured(stored, expected) -> None:
    """A row written by an older panel could hold "false" or 0 rather than a JSON boolean."""
    import json as _json

    from app.models import PanelSetting

    with session_scope() as db:
        db.add(
            PanelSetting(
                key=agent_endpoint.AGENT_ENDPOINT_KEY,
                value=_json.dumps(
                    {
                        "scheme": "https",
                        "host": "legacy.example.com",
                        "port": None,
                        "verify_tls": stored,
                    }
                ),
            )
        )
        db.commit()
        assert agent_endpoint.effective(db, make_settings()).verify_tls is expected


def test_probe_passes_verify_false_to_httpx(monkeypatch) -> None:
    """The probe must test the policy that is about to be saved, not the strict default.

    A probe that verified while the router will not would report "unreachable" for an endpoint
    that works, and the operator would go and change a setting that was already correct.
    """
    seen: dict = {}

    class Response:
        status_code = 200

        def json(self):
            return {"status": "ok", "version": "1.0.0"}

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen.update(kwargs)
        return Response()

    monkeypatch.setattr("httpx.get", fake_get)
    result = agent_endpoint.probe("https://self.example.com", verify_tls=False)
    assert result["ok"] is True
    assert seen["verify"] is False
    # And the strict default is still strict.
    seen.clear()
    agent_endpoint.probe("https://self.example.com")
    assert seen["verify"] is True
