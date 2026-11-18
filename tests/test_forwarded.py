"""The client address rule: forwarded headers are believed only behind a trusted proxy.

This is audit finding F1 in test form. Before it, client_ip() read the LEFTMOST
X-Forwarded-For entry, so a client that rotated the header reset its own rate-limit bucket on
every request and could write any address it liked into the audit log.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

from app import forwarded
from app.config import Settings


def make_request(peer: str, headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (peer, 4444),
        "server": ("panel.test", 80),
    }
    return Request(scope)


def settings_for(**overrides) -> Settings:
    params = {
        "env": "test",
        "panel_url": "http://panel.test",
        "trust_proxy_headers": True,
        "trusted_proxies": ["127.0.0.1", "::1"],
        "forwarded_allow_hops": 1,
    }
    params.update(overrides)
    return Settings(**params)


# ------------------------------------------------------------------ normalisation
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        (" 127.0.0.1 ", "127.0.0.1"),
        ("::1", "::1"),
        ("[::1]", "::1"),
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("203.0.113.9", "203.0.113.9"),
        ("not-an-ip", None),
        ("", None),
        (None, None),
        ("1.2.3.4:80", None),
    ],
)
def test_normalize_ip(raw, expected) -> None:
    assert forwarded.normalize_ip(raw) == expected


# ------------------------------------------------------------------ the trust rule
def test_forwarded_header_from_an_untrusted_peer_is_ignored() -> None:
    request = make_request("8.8.8.8", {"X-Forwarded-For": "1.2.3.4"})
    assert forwarded.client_ip(request, settings_for()) == "8.8.8.8"


def test_forwarded_header_from_a_trusted_peer_is_believed() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-For": "1.2.3.4"})
    assert forwarded.client_ip(request, settings_for()) == "1.2.3.4"


def test_the_rightmost_hop_wins_not_the_leftmost() -> None:
    """A client-supplied prefix must not be able to name itself."""
    request = make_request("127.0.0.1", {"X-Forwarded-For": "9.9.9.9, 1.2.3.4"})
    assert forwarded.client_ip(request, settings_for()) == "1.2.3.4"


def test_two_hops_are_stripped_when_two_proxies_are_configured() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-For": "9.9.9.9, 10.0.0.5, 1.2.3.4"})
    assert forwarded.client_ip(request, settings_for(forwarded_allow_hops=2)) == "10.0.0.5"


def test_a_chain_shorter_than_the_hop_count_fails_closed_to_the_peer() -> None:
    """Too few entries means the proxies we trust are not all in the chain, so its leftmost
    entry is whatever the client typed. Reading it would hand identity back to the attacker."""
    request = make_request("10.9.8.7", {"X-Forwarded-For": "1.2.3.4"})
    assert forwarded.client_ip(request, settings_for(forwarded_allow_hops=3)) == "10.9.8.7"


def test_a_chain_with_exactly_the_hop_count_still_resolves() -> None:
    """Two hops means the chain holds the client plus the address the first proxy saw:
    [client, proxy1]. Neither entry is a bare client assertion."""
    request = make_request("127.0.0.1", {"X-Forwarded-For": "9.9.9.9, 10.0.0.5"})
    assert forwarded.client_ip(request, settings_for(forwarded_allow_hops=2)) == "9.9.9.9"


def test_trust_can_be_switched_off_entirely() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-For": "1.2.3.4"})
    assert forwarded.client_ip(request, settings_for(trust_proxy_headers=False)) == "127.0.0.1"


def test_no_forwarded_header_means_the_peer() -> None:
    request = make_request("10.1.2.3")
    assert forwarded.client_ip(request, settings_for()) == "10.1.2.3"


def test_x_real_ip_is_the_last_resort_behind_a_trusted_peer() -> None:
    request = make_request("127.0.0.1", {"X-Real-IP": "1.2.3.4"})
    assert forwarded.client_ip(request, settings_for()) == "1.2.3.4"


def test_unparsable_entries_are_dropped_rather_than_trusted() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-For": "garbage, 1.2.3.4"})
    assert forwarded.client_ip(request, settings_for()) == "1.2.3.4"


def test_an_ipv6_cidr_trusts_an_ipv6_peer() -> None:
    request = make_request("fd00::1", {"X-Forwarded-For": "1.2.3.4"})
    assert forwarded.client_ip(request, settings_for(trusted_proxies=["fd00::/8"])) == "1.2.3.4"


def test_an_ipv4_network_does_not_trust_an_ipv6_peer() -> None:
    """Same family only: ipaddress raises on a cross-version membership test, and a silent
    True here would trust an entire IPv6 range by accident."""
    request = make_request("fd00::1", {"X-Forwarded-For": "1.2.3.4"})
    assert forwarded.client_ip(request, settings_for(trusted_proxies=["10.0.0.0/8"])) == "fd00::1"


def test_a_malformed_trusted_proxy_entry_is_ignored_not_fatal() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-For": "1.2.3.4"})
    s = settings_for(trusted_proxies=["not-a-cidr", "127.0.0.1"])
    assert forwarded.client_ip(request, s) == "1.2.3.4"


def test_is_trusted_proxy_accepts_a_bare_address_and_a_network() -> None:
    s = settings_for(trusted_proxies=["10.0.0.0/8", "192.0.2.7"])
    assert forwarded.is_trusted_proxy("10.4.4.4", s)
    assert forwarded.is_trusted_proxy("192.0.2.7", s)
    assert not forwarded.is_trusted_proxy("192.0.2.8", s)


def test_peer_ip_survives_a_request_without_a_client() -> None:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": None,
        "server": ("panel.test", 80),
    }
    assert forwarded.peer_ip(Request(scope)) == "unknown"
    assert forwarded.client_ip(Request(scope), settings_for()) == "unknown"


def test_request_scheme_trusts_the_proto_header_from_a_trusted_peer() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-Proto": "https"})
    assert forwarded.request_scheme(request, settings_for()) == "https"


def test_request_scheme_ignores_the_proto_header_from_an_untrusted_peer() -> None:
    request = make_request("8.8.8.8", {"X-Forwarded-Proto": "https"})
    assert forwarded.request_scheme(request, settings_for()) == "http"


def test_request_scheme_ignores_the_proto_header_when_the_flag_is_off() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-Proto": "https"})
    assert forwarded.request_scheme(request, settings_for(trust_forwarded_proto=False)) == "http"


def test_request_scheme_falls_back_to_the_socket_scheme_for_junk() -> None:
    request = make_request("127.0.0.1", {"X-Forwarded-Proto": "gopher"})
    assert forwarded.request_scheme(request, settings_for()) == "http"
