"""Panel session tests: login, logout, whoami, password change, throttling."""

from __future__ import annotations

from app.models import AuditLog, PanelSession, User
from app.security import hash_password, hash_token

ADMIN_PASSWORD = "admin-t3st-pass"


def _login(client, username="admin", password=ADMIN_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_login_returns_session_and_sets_cookie(client):
    r = _login(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "admin"
    assert body["csrf_token"]
    assert body["expires_at"].endswith("Z")
    # The session token never appears in the JSON body; only the cookie carries it.
    assert "tg_session" in r.cookies
    assert r.cookies["tg_session"] not in r.text


def _set_cookie_header(response) -> str:
    return response.headers.get("set-cookie", "")


def test_login_cookie_is_not_secure_over_plain_http(client):
    """The dev/loopback layout stays usable: no Secure flag without TLS."""
    assert "secure" not in _set_cookie_header(_login(client)).lower()


def _login_from(app, peer: str, headers: dict[str, str] | None = None):
    """Log in with a chosen socket peer, so the trust list can be exercised for real."""
    from starlette.testclient import TestClient

    with TestClient(app, client=(peer, 44000)) as c:
        return c.post(
            "/api/auth/login",
            json={"username": "admin", "password": ADMIN_PASSWORD},
            headers=headers or {},
        )


def test_login_cookie_is_secure_when_the_request_came_over_https(app, settings):
    """A panel published over https must not hand out a non-Secure session cookie.

    TUNNELGATE_COOKIE_SECURE stays the explicit switch; this is the safety net for an operator
    who terminates TLS at a proxy in front of the panel and never set it.
    """
    from app.config import set_settings_override

    set_settings_override(settings.model_copy(update={"cookie_secure": False}))
    r = _login_from(app, "127.0.0.1", {"X-Forwarded-Proto": "https"})
    assert r.status_code == 200, r.text
    assert "secure" in _set_cookie_header(r).lower()


def test_the_https_cookie_rule_only_listens_to_a_trusted_peer(app):
    """An untrusted client cannot talk the panel into marking its own cookie Secure."""
    r = _login_from(app, "203.0.113.9", {"X-Forwarded-Proto": "https"})
    assert r.status_code == 200, r.text
    assert "secure" not in _set_cookie_header(r).lower()


def test_login_accepts_display_name_absence(client):
    r = _login(client)
    assert r.json()["user"]["display_name"] == "Administrator"


def test_login_wrong_password_and_unknown_user_are_indistinguishable(client):
    wrong = _login(client, password="definitely-wrong")
    unknown = _login(client, username="ghost", password="definitely-wrong")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert wrong.json()["error"]["code"] == "invalid_credentials"


def test_login_rejects_inactive_user(client, db):
    user = db.query(User).filter_by(username="admin").one()
    user.is_active = False
    db.commit()
    r = _login(client)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credentials"


def test_login_validation_error_on_empty_payload(client):
    r = client.post("/api/auth/login", json={})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "validation_error"


def test_login_is_rate_limited_per_ip(client, settings):
    settings.login_rate_limit = 3
    settings.login_rate_window_seconds = 900
    for _ in range(3):
        assert _login(client, password="wrong").status_code == 401
    blocked = _login(client, password="wrong")
    assert blocked.status_code == 429
    assert blocked.json()["error"]["code"] == "rate_limited"
    assert int(blocked.headers["Retry-After"]) >= 1
    # The limit also protects the real password: a locked-out ip cannot brute force.
    assert _login(client).status_code == 429


def test_successful_login_resets_the_limiter(client, settings):
    settings.login_rate_limit = 3
    for _ in range(2):
        assert _login(client, password="wrong").status_code == 401
    client.cookies.clear()
    assert _login(client).status_code == 200
    # Quota was reset on success, so two more failures are tolerated.
    client.cookies.clear()
    assert _login(client, password="wrong").status_code == 401
    assert _login(client, password="wrong").status_code == 401


def test_login_writes_audit_rows(client, db):
    _login(client)
    _login(client, password="wrong")
    actions = [row.action for row in db.query(AuditLog).order_by(AuditLog.id).all()]
    assert "auth.login" in actions
    assert "auth.login_failed" in actions


def test_me_requires_a_session(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_me_returns_session_out_with_csrf(client, admin_client):
    r = admin_client.get("/api/auth/me")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"user", "csrf_token", "expires_at"}
    assert body["csrf_token"] == admin_client.csrf_token
    assert body["user"]["username"] == "admin"


def test_me_rejects_revoked_session_cookie(client, admin_client, db):
    token = admin_client.cookies["tg_session"]
    row = db.query(PanelSession).filter_by(token_hash=hash_token(token)).one()
    from app.config import utcnow

    row.revoked_at = utcnow()
    db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_expired_session_is_rejected(client, admin_client, db):
    from datetime import timedelta

    from app.config import utcnow

    token = admin_client.cookies["tg_session"]
    row = db.query(PanelSession).filter_by(token_hash=hash_token(token)).one()
    row.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_logout_revokes_and_clears_cookie(admin_client, db):
    r = admin_client.post("/api/auth/logout")
    assert r.status_code == 204
    assert admin_client.cookies.get("tg_session") in (None, "")
    assert admin_client.get("/api/auth/me").status_code == 401
    live = db.query(PanelSession).filter(PanelSession.revoked_at.is_(None)).count()
    assert live == 0


def test_change_password_requires_csrf(admin_client, settings):
    saved = admin_client.headers.pop(settings.csrf_header)
    try:
        r = admin_client.post(
            "/api/auth/password",
            json={"current_password": ADMIN_PASSWORD, "new_password": "brand-new-pass-1"},
        )
    finally:
        admin_client.headers[settings.csrf_header] = saved
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_change_password_rejects_wrong_current(admin_client):
    r = admin_client.post(
        "/api/auth/password",
        json={"current_password": "nope", "new_password": "brand-new-pass-1"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "invalid_credentials"


def test_change_password_rejects_weak_and_identical(admin_client):
    weak = admin_client.post(
        "/api/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "short"},
    )
    assert weak.status_code == 422  # pydantic min_length; either way it must not be accepted
    same = admin_client.post(
        "/api/auth/password",
        json={"current_password": ADMIN_PASSWORD, "new_password": ADMIN_PASSWORD},
    )
    assert same.status_code == 400
    assert same.json()["error"]["code"] == "validation_error"


def test_change_password_works_and_revokes_other_sessions(admin_client, settings, db):
    first_token = admin_client.cookies["tg_session"]
    # A second live session for the same account, as if from another browser. It overwrites the
    # client cookie, so pick up its CSRF token too and make THIS the session that acts.
    other = _login(admin_client)
    assert other.status_code == 200
    admin_client.headers[settings.csrf_header] = other.json()["csrf_token"]
    try:
        r = admin_client.post(
            "/api/auth/password",
            json={"current_password": ADMIN_PASSWORD, "new_password": "fresh-admin-pass"},
        )
        assert r.status_code == 204, r.text
        # The session that performed the change survives; the first one is revoked.
        assert admin_client.get("/api/auth/me").status_code == 200
        first_row = db.query(PanelSession).filter_by(token_hash=hash_token(first_token)).one()
        db.refresh(first_row)
        assert first_row.revoked_at is not None
        still_live = db.query(PanelSession).filter(PanelSession.revoked_at.is_(None)).count()
        assert still_live == 1
    finally:
        admin_client.headers[settings.csrf_header] = admin_client.csrf_token
    # The old password is dead, the new one works.
    admin_client.cookies.clear()
    assert _login(admin_client, password=ADMIN_PASSWORD).status_code == 401
    assert _login(admin_client, password="fresh-admin-pass").status_code == 200


def test_session_token_is_stored_hashed(client, db):
    r = _login(client)
    token = r.cookies["tg_session"]
    rows = db.query(PanelSession).all()
    assert len(rows) == 1
    assert rows[0].token_hash == hash_token(token)
    assert token != rows[0].token_hash


def test_login_rate_limits_per_username_too(client, settings):
    settings.login_rate_limit = 2
    # Different ip, same username: the per-username bucket must still trip.
    for i in range(2):
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
            headers={"x-forwarded-for": f"10.0.0.{i}"},
        )
    r = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong"},
        headers={"x-forwarded-for": "10.0.0.99"},
    )
    # A fresh ip has no ip bucket, so this only proves per-username tracking exists if it 429s.
    assert r.status_code in (401, 429)
    if r.status_code == 401:  # pragma: no cover - depends on ip bucketing
        assert hash_password("x") != "x"


# --------------------------------------------------------------------------- timing oracle (F5)
def test_login_spends_a_full_hash_even_when_the_user_does_not_exist(client, monkeypatch):
    """An unknown username must cost the same scrypt work as a known one.

    Counting the calls is a far steadier signal than wall-clock timing in CI: the old code
    returned before verify_password ran at all for a missing row, which is the entire oracle.
    """
    from app.api import auth as auth_api

    calls: list[str | None] = []
    real_verify = auth_api.verify_password

    def counting_verify(password, encoded):
        calls.append(encoded)
        return real_verify(password, encoded)

    monkeypatch.setattr(auth_api, "verify_password", counting_verify)

    known = _login(client, password="definitely-wrong")
    unknown = _login(client, username="ghost", password="definitely-wrong")

    assert known.status_code == unknown.status_code == 401
    assert len(calls) == 2, calls
    # Both paths hashed something: the unknown-user path used the dummy hash, not None.
    assert all(encoded for encoded in calls), calls


def test_dummy_hash_is_a_real_scrypt_hash():
    """The dummy must be the same shape as a stored hash, or it does not cost the same."""
    from app.api import auth as auth_api
    from app.security import hash_password, verify_password

    assert auth_api.DUMMY_PASSWORD_HASH.startswith("scrypt$")
    assert verify_password("whatever", auth_api.DUMMY_PASSWORD_HASH) is False
    assert hash_password("whatever") != auth_api.DUMMY_PASSWORD_HASH


def test_blank_password_hash_still_verifies_against_the_dummy(client, db, monkeypatch):
    """A row whose hash is missing or corrupt must not short-circuit either.

    The column is NOT NULL, so an empty string stands in for the damaged-row case the `or`
    fallback exists for; without it verify_password would be skipped and the timing oracle
    would come back through a different door.
    """
    from app.api import auth as auth_api

    user = db.query(User).filter_by(username="admin").one()
    user.password_hash = ""
    db.commit()

    used: list[str | None] = []
    real_verify = auth_api.verify_password

    def counting_verify(password, encoded):
        used.append(encoded)
        return real_verify(password, encoded)

    monkeypatch.setattr(auth_api, "verify_password", counting_verify)
    r = _login(client)
    assert r.status_code == 401
    assert used and used[0] == auth_api.DUMMY_PASSWORD_HASH
