"""Inbound checks for every HTTP request: Host allowlist, Origin allowlist, Bearer token.

Applies to the whole app (MCP endpoint and /config), not just the MCP route. The SDK's
own DNS-rebinding check is disabled in app.py because, left at its default, it only
accepts localhost Host headers and would 421 every request behind a public hostname.

Rules:
* /healthz (GET/HEAD) is open and skips the Host check, so load balancers and the Docker
  HEALTHCHECK (which use internal Host headers) can probe it. It reveals nothing.
* Host: if MCP_ALLOWED_HOSTS is set, the Host header must match (host or host:* entries).
  With auth disabled (loopback dev) only localhost names are accepted, which blocks
  DNS-rebinding from a browser.
* Origin: server-to-server clients (Agent Studio, Claude Code) send none. A request that
  does carry an Origin must match MCP_ALLOWED_ORIGINS, otherwise 403 - the spec's MUST.
* Authorization: Bearer <token>, compared in constant time against MCP_AUTH_TOKENS.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .settings import Settings

logger = logging.getLogger(__name__)

LOCAL_HOSTS = ["127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*", "[::1]", "[::1]:*"]
# Headers whose meaning must be unambiguous: the SDK, this middleware and the tools must all
# see the same value, so a request repeating any of them is rejected.
SINGLE_VALUED = (b"authorization", b"mcp-session-id", b"x-oic-config-id", b"host")


def principal_of(authorization: str | None) -> str:
    """Stable, non-reversible id for the Bearer token a request used. Uploads and session
    state are scoped to it, so separate tokens are separate tenants."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return "anonymous"  # only reachable with auth disabled (loopback dev)
    return hashlib.sha256(token.strip().encode()).hexdigest()[:32]


def _host_matches(host: str, allowed: list[str]) -> bool:
    host = host.lower()
    for entry in allowed:
        if entry.endswith(":*"):
            base = entry[:-2]
            if host == base or host.startswith(base + ":"):
                return True
        elif host == entry:
            return True
    return False


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.auth_disabled = settings.mcp_auth_disabled
        self.tokens = [t.encode() for t in settings.auth_tokens]
        self.origins = set(settings.allowed_origins)
        hosts = settings.allowed_hosts
        self.hosts = hosts or (LOCAL_HOSTS if self.auth_disabled else [])

    async def _reject(self, send: Send, status: int, message: str, *, bearer_challenge: bool = False) -> None:
        body = json.dumps({"error": message}).encode()
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        if bearer_challenge:
            headers.append((b"www-authenticate", b'Bearer realm="oic-mcp"'))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    def _token_ok(self, authorization: str) -> bool:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return False
        candidate = token.strip().encode()
        # compare against every token so timing does not reveal which (if any) matched
        return any([hmac.compare_digest(candidate, t) for t in self.tokens])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)

        if scope["path"] == "/healthz" and scope["method"] in ("GET", "HEAD"):
            await self.app(scope, receive, send)
            return

        names = [name.lower() for name, _ in scope.get("headers", [])]
        if any(names.count(h) > 1 for h in SINGLE_VALUED):
            await self._reject(send, 400, "Duplicate Authorization, Host, Mcp-Session-Id or X-OIC-Config-Id header")
            return

        if self.hosts and not _host_matches(headers.get("host", ""), self.hosts):
            logger.warning("Rejected request with Host %r", headers.get("host", "")[:100])
            await self._reject(send, 421, "Invalid Host header")
            return

        origin = headers.get("origin")
        if origin and origin.rstrip("/") not in self.origins:
            logger.warning("Rejected request with Origin %r", origin[:100])
            await self._reject(send, 403, "Origin not allowed")
            return

        if not self.auth_disabled and not self._token_ok(headers.get("authorization", "")):
            await self._reject(send, 401, "Missing or invalid bearer token", bearer_challenge=True)
            return

        await self.app(scope, receive, send)
