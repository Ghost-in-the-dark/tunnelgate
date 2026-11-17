"""Observed tunnel state, read from the kernel - never from a router self-report.

ss is the ground truth for "is a reverse listener up": the router can claim anything in a
heartbeat, but the listening socket either exists on this host or it does not.
"""

from __future__ import annotations

import contextlib
import http.client
import logging
import re
import subprocess
import threading

from ..config import get_settings

log = logging.getLogger(__name__)

SS_TIMEOUT_SECONDS = 5.0

_ADDR_RE = re.compile(r"^(?:\[[^\]]+\]|[^\s:]+):(\d+)$")
_PROC_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def parse_ss_listeners(output: str) -> dict[int, dict]:
    """Parse ss -Hltnp output into {port: {port, address, pid, program}}.

    Local addresses may be 127.0.0.1:20001, *:22, [::]:22 or 127.0.0.53%lo:53; the port is
    whatever follows the last colon in the address field. The process column is optional
    (ss -p needs privileges on some systems).
    """
    listeners: dict[int, dict] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        address_field = next((f for f in fields if _ADDR_RE.match(f)), None)
        if address_field is None:
            continue
        address, _, port_text = address_field.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:  # pragma: no cover - the regex already guarantees digits
            continue
        match = _PROC_RE.search(line)
        listeners[port] = {
            "port": port,
            "address": address,
            "pid": int(match.group(2)) if match else None,
            "program": match.group(1) if match else None,
        }
    return listeners


def list_listening_tunnels() -> dict[int, dict]:
    """All listening TCP sockets on this host, in one ss invocation.

    A missing ss binary (or a non-zero exit) yields an empty map: callers then treat every
    tunnel as down, which is the fail-safe direction for status reporting.
    """
    try:
        proc = subprocess.run(
            ["ss", "-Hltnp"],
            capture_output=True,
            text=True,
            timeout=SS_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        log.debug("ss is unavailable; treating every tunnel as down", exc_info=True)
        return {}
    if proc.returncode != 0:
        log.debug("ss exited with %s: %s", proc.returncode, proc.stderr.strip()[:200])
        return {}
    return parse_ss_listeners(proc.stdout)


def is_tunnel_up(port: int | None) -> bool:
    """True when this host holds a listening socket on the given port."""
    if not port:
        return False
    return int(port) in list_listening_tunnels()


def health_check(port: int | None, path: str | None = None, timeout: float | None = None) -> bool:
    """HTTP GET against LuCI through the tunnel.

    Healthy means "LuCI answered": any 2xx/3xx, plus 401 because a login prompt is exactly what
    a live LuCI returns for an unauthenticated request. Connection refused, reset or timeout is
    unhealthy. The request runs in a daemon thread so a half-open socket cannot pin the caller
    for longer than the timeout.
    """
    s = get_settings()
    if not port:
        return False
    target_path = path or s.health_path or "/"
    request_timeout = float(timeout if timeout is not None else s.health_timeout_seconds)
    result = {"healthy": False}

    def _probe() -> None:
        conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=request_timeout)
        try:
            conn.request(
                "GET",
                target_path,
                headers={"User-Agent": "tunnelgate-health/1", "Connection": "close"},
            )
            response = conn.getresponse()
            result["healthy"] = 200 <= response.status < 400 or response.status == 401
        except (OSError, http.client.HTTPException, ValueError):
            result["healthy"] = False
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    thread = threading.Thread(target=_probe, name=f"tg-health-{port}", daemon=True)
    thread.start()
    thread.join(request_timeout + 1.0)
    if thread.is_alive():
        log.debug("health check on port %s did not finish within %.1fs", port, request_timeout)
        return False
    return bool(result["healthy"])
