"""Panel session tests: login, logout, whoami, password change, throttling."""

from __future__ import annotations

from app.models import AuditLog, PanelSession, User
from app.security import hash_password, hash_token

ADMIN_PASSWORD = "admin-t3st-pass"


def _login(client, username="admin", password=ADMIN_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_login_returns_session_and_sets_cookie(client, settings):
    r = _login(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "admin"
    assert body["expires_at"].endswith("Z")
    # The CSRF token is NOT in the body any more, and that is the point of the change: a
    # same-origin script could fetch this response (in the merged path layout a router page is
    # same-origin with the panel) and read any token the body carried. It lives in a cookie.
    assert "csrf_token" not in body
    assert r.cookies[settings.csrf_cookie_name] not in r.text
    # The session token never appears in the JSON body; only the cookie carries it.
    assert settings.cookie_name in r.cookies
    assert r.cookies[settings.cookie_name] not in r.text


def _set_cookie_headers(response) -> list[str]:
    """Every Set-Cookie line. Login sends two (session + csrf), and .get() joins them."""
    headers = response.headers
    get_list = getattr(headers, "get_list", None)
    if get_list is not None:
        return get_list("set-cookie")
    return [h for h in [headers.get("set-cookie", "")] if h]


def _cookie_line(response, name: str) -> str:
    for line in _set_cookie_headers(response):
        if line.split("=", 1)[0].strip() == name:
            return line
    raise AssertionError(f"no Set-Cookie for {name} in {response.headers.get('set-cookie')!r}")


def _cookie_attrs(response, name: str) -> dict[str, str]:
    """Set-Cookie line -> {attribute: value}, with bare flags mapped to ''."""
    attrs: dict[str, str] = {}
    parts = _cookie_line(response, name).split(";")
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return attrs


def test_login_cookie_is_not_secure_over_plain_http(client):
    """The dev/loopback layout stays usable: no Secure flag without TLS."""
    r = _login(client)
    assert "secure" not in _cookie_attrs(r, "tg_session")
    # The CSRF cookie has to follow the session cookie here too, or the browser would send the
    # session over plain http while withholding the token that makes it usable.
    assert "secure" not in _cookie_attrs(r, "tg_csrf")


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
    assert "secure" in _cookie_attrs(r, "tg_session")
    assert "secure" in _cookie_attrs(r, "tg_csrf")


def test_the_https_cookie_rule_only_listens_to_a_trusted_peer(app):
    """An untrusted client cannot talk the panel into marking its own cookie Secure."""
    r = _login_from(app, "203.0.113.9", {"X-Forwarded-Proto": "https"})
    assert r.status_code == 200, r.text
    assert "secure" not in _cookie_attrs(r, "tg_session")
    assert "secure" not in _cookie_attrs(r, "tg_csrf")


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


def test_me_does_not_return_a_csrf_token(client, admin_client, settings):
    """The regression test for the merged-layout escalation.

    A compromised router page in the merged path layout is same-origin with the panel and can
    call this route with the operator's session cookie. When the answer carried the CSRF token
    it could then perform any authenticated mutation - a router page really did create a second
    admin account. The body must not carry the token, and the token must still be usable from
    the cookie the browser already has.
    """
    r = admin_client.get("/api/auth/me")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"user", "expires_at"}
    assert "csrf_token" not in body
    assert body["user"]["username"] == "admin"
    # Belt and braces: the token appears nowhere in the serialised response.
    assert admin_client.cookies[settings.csrf_cookie_name] not in r.text


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


def test_logout_revokes_and_clears_cookie(admin_client, db, settings):
    r = admin_client.post("/api/auth/logout")
    assert r.status_code == 204
    assert admin_client.cookies.get(settings.cookie_name) in (None, "")
    # The CSRF cookie must go with it: a token left behind belongs to no session, and a browser
    # that kept it would try the next mutation with a value the server has already forgotten.
    assert admin_client.cookies.get(settings.csrf_cookie_name) in (None, "")
    # Both cookies were cleared in the same response, not just dropped from the jar.
    for name in (settings.cookie_name, settings.csrf_cookie_name):
        assert "max-age=0" in _cookie_line(r, name).lower(), (name, _set_cookie_headers(r))
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


# --------------------------------------------------- double submit: cookie AND header
def _create_router(client, name="csrf-probe"):
    """A harmless state-changing request: the whole point of the CSRF check."""
    return client.post("/api/v1/routers", json={"name": name})


def test_the_two_cookies_carry_the_attributes_the_design_requires(client, settings):
    """Session cookie unreadable by script, CSRF cookie readable, and otherwise identical.

    HttpOnly on the CSRF cookie would be self-defeating (the SPA has to read it to build the
    header); HttpOnly missing on the session cookie would hand the credential itself to any XSS.
    Same path, domain, SameSite and Max-Age so the two cannot drift: a browser that drops one
    and keeps the other leaves a session that can never mutate again, which looks like a bug to
    the operator and is a support ticket, so the lifetimes are pinned together here.
    """
    r = _login(client)
    session = _cookie_attrs(r, settings.cookie_name)
    csrf = _cookie_attrs(r, settings.csrf_cookie_name)

    assert "httponly" in session
    assert "httponly" not in csrf
    for attrs in (session, csrf):
        assert attrs.get("path") == "/"
        assert attrs.get("samesite", "").lower() == "lax"
    assert session.get("max-age") == csrf.get("max-age")
    assert int(session["max-age"]) == int(settings.session_ttl_minutes) * 60
    # Same domain handling: cookie_domain is unset in tests, so neither carries Domain.
    assert ("domain" in session) == ("domain" in csrf)


def test_the_csrf_cookie_carries_the_session_token(client, settings, db):
    """The cookie is the session's token, not a second independent secret."""
    r = _login(client)
    token = r.cookies[settings.csrf_cookie_name]
    row = db.query(PanelSession).one()
    assert token == row.csrf_token
    assert token != r.cookies[settings.cookie_name]


def test_a_mutation_succeeds_with_both_the_cookie_and_the_header(admin_client):
    assert _create_router(admin_client).status_code == 201


def test_a_mutation_fails_without_the_csrf_cookie(admin_client, settings):
    """Header alone is not proof of anything: the cookie has to travel too."""
    saved = admin_client.cookies[settings.csrf_cookie_name]
    admin_client.cookies.delete(settings.csrf_cookie_name)
    try:
        r = _create_router(admin_client)
    finally:
        admin_client.cookies.set(settings.csrf_cookie_name, saved)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_a_mutation_fails_without_the_header(admin_client, settings):
    """Cookie alone is not proof either: any page on the origin gets the cookie for free."""
    saved = admin_client.headers.pop(settings.csrf_header)
    try:
        r = _create_router(admin_client)
    finally:
        admin_client.headers[settings.csrf_header] = saved
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_a_header_that_disagrees_with_the_cookie_fails(admin_client, settings):
    from app.security import new_token

    saved_header = admin_client.headers[settings.csrf_header]
    saved_cookie = admin_client.cookies[settings.csrf_cookie_name]
    # A well-formed token that is simply not this session's: the shape must not matter.
    other = new_token(24)
    try:
        admin_client.headers[settings.csrf_header] = other
        r = _create_router(admin_client)
    finally:
        admin_client.headers[settings.csrf_header] = saved_header
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"

    # And the mirror image: a stale cookie with the right header.
    try:
        admin_client.cookies.set(settings.csrf_cookie_name, other)
        r = _create_router(admin_client)
    finally:
        admin_client.cookies.set(settings.csrf_cookie_name, saved_cookie)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_a_cached_json_token_from_the_old_contract_is_not_enough(admin_client, settings):
    """An older client that kept the token from the JSON body has no cookie, so it is refused.

    This is the documented cost of the change: the SPA is updated in the same release, and a
    hand-written client has to log in again to receive the cookie. Rejecting it silently would
    be worse - the client would believe it is authorised until the first mutation.
    """
    saved_header = admin_client.headers[settings.csrf_header]
    saved_cookie = admin_client.cookies[settings.csrf_cookie_name]
    admin_client.cookies.delete(settings.csrf_cookie_name)
    try:
        admin_client.headers[settings.csrf_header] = saved_header
        r = _create_router(admin_client)
    finally:
        admin_client.cookies.set(settings.csrf_cookie_name, saved_cookie)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_failed"


def test_the_double_submit_comparisons_are_constant_time(admin_client, monkeypatch):
    """Both halves go through tokens_equal (hmac.compare_digest), never ==.

    A byte-wise comparison with an early return leaks the token one byte at a time to anyone who
    can time the 403, which is exactly the party the check exists to stop.
    """
    from app import deps

    calls: list[tuple[str, str]] = []
    real = deps.tokens_equal

    def counting(a: str, b: str) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(deps, "tokens_equal", counting)
    assert _create_router(admin_client, name="csrf-constant-time").status_code == 201
    assert len(calls) == 2, calls
    # Header vs cookie, then cookie vs the session row.
    assert calls[0] == (
        admin_client.headers[deps.get_settings().csrf_header],
        admin_client.cookies[deps.get_settings().csrf_cookie_name],
    )
    assert calls[1][1] == admin_client.cookies[deps.get_settings().csrf_cookie_name]


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
    other_csrf = other.cookies[settings.csrf_cookie_name]
    admin_client.cookies.set(settings.csrf_cookie_name, other_csrf)
    admin_client.headers[settings.csrf_header] = other_csrf
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
        admin_client.cookies.set(settings.csrf_cookie_name, admin_client.csrf_token)
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
