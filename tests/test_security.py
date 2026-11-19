"""Unit tests for the credential helpers in app/security.py.

These exist because the accepted wire shapes were measured on real devices, not assumed: the
Basic-auth cases below are the exact payloads stock OpenWrt's uclient-fetch sends.
"""

from __future__ import annotations

import base64

import pytest

from app.security import WWW_AUTHENTICATE_BASIC, basic_auth_username


def _basic(payload: str) -> str:
    return "Basic " + base64.b64encode(payload.encode()).decode()


# ------------------------------------------------------------------- payload shapes
def test_colon_less_payload_is_the_username():
    """The shape uclient-fetch actually sends: base64(TOKEN), no colon.

    Measured on OpenWrt 19.07.10/22.03.7/23.05.5/24.10.1 for both the URL-userinfo retry and
    --user=TOKEN --password=''. Rejecting it made every stock device fail with 401 forever.
    """
    assert basic_auth_username(_basic("tok123")) == "tok123"


def test_trailing_colon_is_the_same_username():
    """base64("TOKEN:") and base64("TOKEN") are the same credential, empty password."""
    assert basic_auth_username(_basic("tok123:")) == "tok123"


def test_password_half_is_ignored():
    assert basic_auth_username(_basic("tok123:tunnelgate")) == "tok123"


def test_token_needing_base64_characters_survives_the_round_trip():
    """URL-safe tokens can contain characters base64 has to encode; none may be mangled."""
    token = "ab+/=cd-_XYZ.0123"
    assert basic_auth_username(_basic(token)) == token
    assert basic_auth_username(_basic(f"{token}:")) == token


def test_surrounding_whitespace_in_the_username_is_trimmed():
    assert basic_auth_username(_basic("  tok123  ")) == "tok123"


# ------------------------------------------------------------------- rejections
@pytest.mark.parametrize("payload", ["", ":", ":pass", "   "])
def test_an_empty_username_is_not_a_token(payload):
    """A device that authenticated as nobody must not authenticate as anybody."""
    assert basic_auth_username(_basic(payload)) is None


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer abc",
        "Digest username=admin",
        "Basic",
        "Basic ",
        "basic",
        "Basic !!!not-base64",
        "Basic bm9jb2xvbg",  # no padding
    ],
)
def test_a_header_that_is_not_basic_auth_is_simply_absent(header):
    """These run before authentication, so a raise here would be a public 500."""
    assert basic_auth_username(header) is None


def test_base64_containing_invalid_utf8_is_rejected():
    """base64 that decodes to bytes which are not UTF-8 must not become a credential."""
    header = "Basic " + base64.b64encode(b"\xff\xfe\x00").decode()
    assert basic_auth_username(header) is None


def test_the_challenge_is_the_one_uclient_fetch_needs():
    assert WWW_AUTHENTICATE_BASIC == 'Basic realm="tunnelgate"'
