"""Password hashing, opaque tokens, ed25519 key material and login rate limiting.

Design notes:
* Passwords: stdlib scrypt (n=2**14, r=8, p=1) encoded as scrypt$n$r$p$salt$hash.
  No external dependency, constant-time verification, format is self-describing.
* Panel/bootstrap/API tokens: 32 random bytes (256 bit) -> urlsafe base64.
  Only SHA-256 digests are persisted, so a database leak cannot be replayed.
* Router SSH keys: ed25519 generated on demand; the private half is serialised as an
  OpenSSH PEM blob, streamed to the router once and never stored server-side.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
TOKEN_BYTES = 32
MIN_PASSWORD_LENGTH = 8


# --------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    salt_b64 = base64.b64encode(salt).decode()
    digest_b64 = base64.b64encode(dk).decode()
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt_b64}${digest_b64}"


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        scheme, n, r, p, salt_b64, hash_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(hash_b64)
        dk = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if password.strip() != password:
        return "password must not start or end with whitespace"
    return None


# --------------------------------------------------------------------------- tokens
def new_token(nbytes: int = TOKEN_BYTES) -> str:
    """Cryptographically strong, URL-safe opaque token (never logged, never stored raw)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------- basic auth
# The challenge every router-facing 401 must carry. uclient-fetch (OpenWrt's wget) only retries
# with credentials after it has seen a challenge, so without this header the operator sees a bare
# 401 and the credential it was already configured with is never sent.
WWW_AUTHENTICATE_BASIC = 'Basic realm="tunnelgate"'


def basic_auth_username(authorization: str | None) -> str | None:
    """The username of an HTTP Basic Authorization header, or None if there is not one.

    The bootstrap and api tokens travel as this username with an empty password, because that is
    the only credential channel that works on every stock OpenWrt image: curl is absent there and
    uclient-fetch only grew --header in 24.10, while --user/--password works on all of them.

    A colon-less payload is ACCEPTED as "username with an empty password". RFC 7617 specifies
    user-id ":" password, but real clients drop the colon when the password is empty: this was
    measured on stock OpenWrt 19.07.10 / 22.03.7 / 23.05.5 / 24.10.1 through a logging proxy, and
    every one of them sends base64(TOKEN) with no colon for both the URL-userinfo retry and
    --user=TOKEN --password=''. Rejecting that payload made the router answer 401 forever, so the
    acceptance is not leniency - it is the difference between the channel working and not. A
    colon-less payload and "TOKEN:" decode to the same username and are treated identically; the
    password half is never checked either way.

    Defensive by contract: a header that is missing, is not Basic, or is not valid base64 is
    simply "no token" and must never raise. This runs before authentication, so an exception here
    would be a 500 reachable by anyone.
    """
    if not authorization:
        return None
    try:
        scheme, _, encoded = authorization.partition(" ")
        if scheme.strip().lower() != "basic":
            return None
        # validate=True rejects the newlines and stray whitespace that base64.b64decode ignores,
        # so a header mangled in transit is a clean "no token" instead of a corrupt credential.
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8", "strict")
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    # partition() returns sep == "" when there is no colon, which is the uclient-fetch shape:
    # the whole payload is then the username and the password is implicitly empty.
    username, _sep, _password = decoded.partition(":")
    # An empty username is not a token; it means the device authenticated as nobody.
    return username.strip() or None


# --------------------------------------------------------------------------- ssh key material
@dataclass(slots=True)
class KeyPair:
    private_openssh: str
    public_line: str  # "ssh-ed25519 AAAA... comment"
    fingerprint: str  # "SHA256:base64" (same as ssh-keygen -lf)
    comment: str


def generate_ed25519_keypair(comment: str) -> KeyPair:
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.OpenSSH,
        encryption_algorithm=NoEncryption(),
    ).decode()
    pub = (
        key.public_key()
        .public_bytes(encoding=Encoding.OpenSSH, format=PublicFormat.OpenSSH)
        .decode()
    )
    pub_line = pub + " " + comment
    return KeyPair(
        private_openssh=private_pem,
        public_line=pub_line,
        fingerprint=key_fingerprint(pub_line),
        comment=comment,
    )


def _blob_from_public_line(public_line: str) -> bytes:
    parts = public_line.strip().split()
    if len(parts) < 2:
        raise ValueError("malformed public key")
    return base64.b64decode(parts[1])


def key_fingerprint(public_line: str) -> str:
    """OpenSSH style SHA256 fingerprint of the key blob."""
    digest = hashlib.sha256(_blob_from_public_line(public_line)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def authorized_key_line(
    public_line: str,
    *,
    bind_address: str,
    ports: int | tuple[int, ...] | list[int],
    comment: str | None = None,
    extra_options: str = "",
) -> str:
    """Build an authorized_keys line that can only open reverse listeners.

    Why not `restrict`: the `restrict` keyword implies `disable-forwarding`, and
    `permitlisten` is evaluated *after* that blanket denial, so a line containing both
    makes every remote forward fail ("remote port forwarding failed for listen port N",
    reproduced against OpenSSH 10.2). We therefore spell the restrictions out and add one
    `permitlisten` per allocated port (the tunnel port and, when the web console is
    enabled, the console port).

    Remaining surface of this key: it may open exactly those reverse listeners and nothing
    else - no shell (`command="/bin/false"`), no pty, no agent/X11 forwarding, no user rc.

    Local forwarding is pinned to a dead endpoint rather than `permitopen="none"`: sshd
    accepts `none` in sshd_config but NOT as a key option - a line containing
    `permitopen="none"` is rejected wholesale with "bad key options: invalid permission
    port", which silently breaks authentication for every router (reproduced against
    OpenSSH 10.0p2/10.2). Port 1 on loopback has no listener and is not a LuCI endpoint, so
    permitting it keeps the key unusable for pivoting while staying parseable by sshd.
    """
    if isinstance(ports, int):
        ports = (ports,)
    if not ports:
        raise ValueError("at least one permitlisten port is required")
    opts = [
        "no-pty",
        "no-agent-forwarding",
        "no-X11-forwarding",
        "no-user-rc",
        'command="/bin/false"',
        # NOT permitopen="none": sshd accepts that literal only in sshd_config, not as a key
        # option - it rejects the whole line with 'bad key options: invalid permission port'
        # and silently locks every router out. Pinning a dead loopback endpoint keeps -L
        # unusable while staying parseable.
        'permitopen="127.0.0.1:1"',
    ]
    for p in ports:
        opts.append(f'permitlisten="{bind_address}:{int(p)}"')
    if extra_options:
        opts.append(extra_options)
    key = public_line.strip()
    if comment:
        parts = key.split()
        key = " ".join(parts[:2]) + " " + comment
    return ",".join(opts) + " " + key


def console_authorized_key_line(
    public_line: str, *, from_address: str = "127.0.0.1", comment: str = "tunnelgate-console"
) -> str:
    """authorized_keys line installed ON THE ROUTER for the panel's console key.

    The router side is usually dropbear, which understands only a small option subset
    (from=, no-port-forwarding, no-agent-forwarding, no-X11-forwarding, no-pty). Anything
    OpenSSH-specific (no-user-rc, restrict, permitopen) would make dropbear reject the key
    outright, so the option set is deliberately conservative. The pty is intentionally
    allowed: an interactive shell is the whole point of this key.
    """
    opts = [
        f'from="{from_address}"',
        "no-port-forwarding",
        "no-agent-forwarding",
        "no-X11-forwarding",
    ]
    key = public_line.strip()
    parts = key.split()
    body = " ".join(parts[:2])
    return ",".join(opts) + " " + body + " " + comment


# --------------------------------------------------------------------------- secret store
def master_key(settings=None) -> bytes:
    """32-byte AES key used to encrypt secrets that must live at rest.

    Production must set TUNNELGATE_SECRET_KEY (base64 or any passphrase: it is stretched
    with SHA-256). In development the key is generated once into <data_dir>/secret.key so a
    checkout keeps working without configuration; that fallback is refused when
    settings.env == "production".
    """
    from .config import get_settings

    s = settings or get_settings()
    raw = (s.secret_key or "").strip()
    if raw:
        return hashlib.sha256(("tunnelgate:" + raw).encode()).digest()
    if s.env == "production":
        raise RuntimeError(
            "TUNNELGATE_SECRET_KEY must be set in production: it protects the console "
            "private keys stored in the database"
        )
    path = Path(s.data_dir) / "secret.key"
    if path.exists():
        data = path.read_bytes().strip()
        if data:
            return hashlib.sha256(b"tunnelgate:file:" + data).digest()
    data = base64.urlsafe_b64encode(secrets.token_bytes(32))
    Path(s.data_dir).mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    with contextlib.suppress(OSError):  # pragma: no cover - exotic filesystems
        path.chmod(0o600)
    return hashlib.sha256(b"tunnelgate:file:" + data).digest()


SECRET_PREFIX = "v1."


def encrypt_secret(plaintext: str, settings=None) -> str:
    """AES-256-GCM encrypt a secret for storage. Output: v1.<b64(nonce||ciphertext)>."""
    key = master_key(settings)
    nonce = secrets.token_bytes(12)
    blob = AESGCM(key).encrypt(nonce, plaintext.encode(), b"tunnelgate")
    return SECRET_PREFIX + base64.urlsafe_b64encode(nonce + blob).decode()


def decrypt_secret(token: str | None, settings=None) -> str | None:
    if not token:
        return None
    if not token.startswith(SECRET_PREFIX):
        raise ValueError("unknown secret format")
    key = master_key(settings)
    raw = base64.urlsafe_b64decode(token[len(SECRET_PREFIX) :])
    return AESGCM(key).decrypt(raw[:12], raw[12:], b"tunnelgate").decode()


# --------------------------------------------------------------------------- rate limiting
@dataclass
class _Bucket:
    hits: list[float] = field(default_factory=list)


class RateLimiter:
    """In-memory sliding-window limiter for login attempts (per ip and per ip+username)."""

    def __init__(self, limit: int = 10, window_seconds: int = 900) -> None:
        self.limit = limit
        self.window = window_seconds
        self._buckets: dict[str, _Bucket] = {}

    def _prune(self, bucket: _Bucket, now: float) -> None:
        cutoff = now - self.window
        bucket.hits = [t for t in bucket.hits if t >= cutoff]

    def check(self, *keys: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds). Does not consume quota."""
        now = time.monotonic()
        retry = 0
        for key in keys:
            bucket = self._buckets.setdefault(key, _Bucket())
            self._prune(bucket, now)
            if len(bucket.hits) >= self.limit:
                retry = max(retry, int(self.window - (now - bucket.hits[0])) + 1)
        return retry == 0, retry

    def hit(self, *keys: str) -> None:
        now = time.monotonic()
        for key in keys:
            bucket = self._buckets.setdefault(key, _Bucket())
            self._prune(bucket, now)
            bucket.hits.append(now)

    def reset(self, *keys: str) -> None:
        for key in keys:
            self._buckets.pop(key, None)

    def clear(self) -> None:
        self._buckets.clear()
