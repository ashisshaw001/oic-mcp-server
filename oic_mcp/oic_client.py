"""Per-environment OIC REST client.

One OICClient per configured environment (INI section). It owns that environment's
OAuth token cache and HTTP connection pool, so switching environments never mixes
credentials. Every OIC endpoint path used by the server lives in this module.

Security properties (all covered by tests):
* Requests only ever go to the configured OIC host: paths are validated and the
  resolved URL's scheme/host/port must match the base URL.
* Identifiers are percent-encoded as single path segments ('.' and '..' are refused),
  so a value like "../../x" cannot change which endpoint is called.
* Redirects are followed manually (OIC 307s design-time calls to the region's shared
  design host) but the bearer token is only forwarded to the same host, that design
  host, or an explicitly allow-listed suffix.
* The token endpoint is never redirected to, and credentials are never logged.
* Every response body is read with a byte cap (decompressed size), so a hostile or
  broken endpoint cannot exhaust memory.
"""

from __future__ import annotations

import asyncio
import io
import logging
import random
import re
import ssl
import time
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from .config_parser import InstanceConfig

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
PAGE_SIZE = 100
MAX_CATALOGUE_PAGES = 200  # 20,000 integrations
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_TOKEN_RESPONSE_BYTES = 1024 * 1024
DESIGN_CACHE_SIZE = 32
SCHEDULE_CONCURRENCY = 6

INTEGRATIONS = "/ic/api/integration/v1/integrations"
MONITORING = "/ic/api/integration/v1/monitoring"

_SSL_CONTEXT: ssl.SSLContext | None = None
_BACKGROUND: set[asyncio.Task[Any]] = set()  # keep close tasks referenced until they finish


def as_list(value: Any) -> list[Any]:
    """OIC 'items' should be a list; tolerate anything else instead of crashing."""
    return value if isinstance(value, list) else []


def shared_ssl_context() -> ssl.SSLContext:
    """One SSL context for every client: each new context costs ~1.7 MB and ~60 ms."""
    global _SSL_CONTEXT
    if _SSL_CONTEXT is None:
        _SSL_CONTEXT = httpx.create_ssl_context()
    return _SSL_CONTEXT


def region_design_host(host: str) -> str | None:
    """<name>.integration.<region>.ocp.oraclecloud.com -> design.integration.<region>.ocp.oraclecloud.com"""
    match = re.fullmatch(r"[^.]+\.integration\.([a-z0-9-]+)\.ocp\.oraclecloud\.com", (host or "").lower())
    return f"design.integration.{match.group(1)}.ocp.oraclecloud.com" if match else None


class OICError(ToolError):
    """An anticipated failure. Subclassing ToolError means the MCP SDK shows this
    message to the model (any other exception is masked as 'Error executing tool')."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        # OIC error text is echoed into messages; a lone UTF-16 surrogate in it would make the
        # SDK fail to serialize the whole response, so replace such characters.
        super().__init__(str(message).encode("utf-8", "replace").decode("utf-8"))
        self.status = status


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def seg(value: str) -> str:
    """Encode a value as exactly one URL path segment. '.' and '..' are refused because
    they are dot-segments even when percent-encoding leaves them unchanged."""
    text = str(value)
    if text.strip() in ("", ".", ".."):
        raise OICError(f"Invalid identifier {text!r}.")
    return quote(text, safe="")


def split_identifier(identifier: str, version: str | None = None) -> tuple[str, str | None]:
    ident = (identifier or "").strip()
    if not ident:
        raise OICError("An integration identifier is required: CODE or CODE|VERSION.")
    code, sep, embedded = ident.partition("|")
    ver = (version or "").strip() or (embedded.strip() if sep else "")
    if not code.strip():
        raise OICError(f"Invalid integration identifier {identifier!r}.")
    return code.strip(), (ver or None)


def version_key(version: str) -> tuple[int, ...]:
    """'01.10.0002' -> (1, 10, 2). Non-numeric parts sort lowest."""
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.\-_]", version or "") if p != "")


def to_oic_datetime(value: str, *, end_of_day: bool = False) -> str:
    """Normalise ISO-8601 / 'YYYY-MM-DD HH:MM:SS' input to OIC's UTC 'YYYY-MM-DD HH:MM:SS'.

    A bare date means the start of that day, or its last second when used as a range end,
    so start=end=2026-09-29 covers the whole day.
    """
    text = (value or "").strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            parsed = datetime.fromisoformat(text + ("T23:59:59" if end_of_day else "T00:00:00"))
        else:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T", 1))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        utc = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise OICError(
            f"Unrecognised date/time {value!r}. Use ISO-8601, e.g. 2026-09-29T14:30:00Z "
            "(no offset = UTC)."
        ) from None
    return f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d} {utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}"


def build_q(filters: dict[str, Any]) -> str | None:
    """OIC's q filter: {key:'value', key2:'value2'} (documented syntax)."""
    parts = []
    for key, value in filters.items():
        if value is None or value == "":
            continue
        text = str(value)
        if any(ch in text for ch in "'{}"):
            raise OICError(f"The value for {key} may not contain quotes or braces.")
        parts.append(f"{key}:'{text}'")
    return "{" + ", ".join(parts) + "}" if parts else None


def unwrap(payload: Any) -> dict[str, Any]:
    """Some tenants wrap list responses in {'content': {...}}."""
    if isinstance(payload, dict):
        content = payload.get("content")
        if isinstance(content, dict) and ("items" in content or "totalResults" in content):
            return content
        return payload
    return {}


def _error_detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return ""
    parts: list[str] = []
    if isinstance(body, dict):
        for key in ("title", "detail", "message", "errorMessage", "error_description"):
            value = body.get(key)
            if isinstance(value, str) and value.strip() and value.strip() not in parts:
                parts.append(value.strip())
        details = body.get("o:errorDetails")
        for item in details if isinstance(details, list) else []:
            if isinstance(item, dict):
                value = item.get("detail") or item.get("title")
                if isinstance(value, str) and value.strip() and value.strip() not in parts:
                    parts.append(value.strip())
    return " - ".join(parts)[:300]


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class OICClient:
    def __init__(
        self,
        cfg: InstanceConfig,
        *,
        timeout: float = 30.0,
        max_retries: int = 2,
        redirect_suffixes: tuple[str, ...] = (),
        catalogue_ttl: float = 120.0,
        allow_insecure: bool = False,
        max_response_bytes: int = 20 * 1024 * 1024,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.cfg = cfg
        self._base = httpx.URL(cfg.base_url)
        self._max_retries = max(0, max_retries)
        self._suffixes = tuple(s.lower() for s in redirect_suffixes)
        self._design_host = region_design_host(self._base.host or "")
        self._allow_insecure = allow_insecure
        self._catalogue_ttl = catalogue_ttl
        self._max_bytes = max_response_bytes
        self._timeout = timeout
        self._transport = transport
        self._http = self._new_http()
        self._inflight = 0
        self._retired = False
        self._token: str | None = None
        self._token_expires = 0.0
        self._token_lock = asyncio.Lock()
        self._catalogue: list[dict[str, Any]] | None = None
        self._catalogue_complete = True
        self._catalogue_at = 0.0
        self._catalogue_lock = asyncio.Lock()
        self._design_cache: OrderedDict[tuple[str, str], tuple[float, Any]] = OrderedDict()

    @property
    def env(self) -> str:
        return self.cfg.name

    def _new_http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,
            transport=self._transport,
            verify=shared_ssl_context(),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    def _pool(self) -> httpx.AsyncClient:
        # A retired client (evicted from the cache while a tool call still holds it) closes its
        # pool whenever it goes idle; reopen it if that call makes another request.
        if self._http.is_closed:
            self._http = self._new_http()
        return self._http

    def retire(self) -> None:
        """Called when the registry drops this client: release the pool as soon as it is idle."""
        self._retired = True
        if self._inflight == 0 and not self._http.is_closed:
            try:
                task = asyncio.get_running_loop().create_task(self._http.aclose())
                _BACKGROUND.add(task)
                task.add_done_callback(_BACKGROUND.discard)
            except RuntimeError:  # no running loop (shutdown)
                pass

    async def aclose(self) -> None:
        await self._http.aclose()

    # --- transport ---------------------------------------------------------

    async def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay = 0.5 * (2**attempt) + random.uniform(0, 0.25)
        if retry_after and retry_after.strip().isdigit():
            delay = min(float(retry_after.strip()), 10.0)
        await asyncio.sleep(delay)

    async def _read_capped(self, resp: httpx.Response, max_bytes: int, target: str) -> httpx.Response:
        """Read a streamed response with a cap on the decompressed size, then return a
        plain in-memory Response (so .json()/.text work as usual)."""
        too_big = f"The {target} response for '{self.env}' is larger than {max_bytes // (1024 * 1024) or 1} MB; narrow the request."
        try:
            declared = resp.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise OICError(too_big)
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise OICError(too_big)
        finally:
            await resp.aclose()
        headers = [
            (k, v)
            for k, v in resp.headers.multi_items()
            if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")
        ]
        return httpx.Response(resp.status_code, headers=headers, content=bytes(body), request=resp.request)

    async def _send(
        self, method: str, url: httpx.URL, *, target: str, max_bytes: int | None = None, **kwargs: Any
    ) -> httpx.Response:
        """One logical request with retries on timeouts, connection errors, 429 and 5xx."""
        self._inflight += 1
        try:
            return await self._send_with_retries(method, url, target=target, max_bytes=max_bytes, **kwargs)
        finally:
            self._inflight -= 1
            if self._retired and self._inflight == 0 and not self._http.is_closed:
                await self._http.aclose()

    async def _send_with_retries(
        self, method: str, url: httpx.URL, *, target: str, max_bytes: int | None, **kwargs: Any
    ) -> httpx.Response:
        attempt = 0
        while True:
            try:
                pool = self._pool()
                request = pool.build_request(method, url, **kwargs)
                streamed = await pool.send(request, stream=True)
                resp = await self._read_capped(streamed, max_bytes or self._max_bytes, target)
            except OICError:
                raise
            except httpx.TimeoutException:
                if attempt < self._max_retries:
                    await self._backoff(attempt, None)
                    attempt += 1
                    continue
                raise OICError(
                    f"{target} did not respond in time for environment '{self.env}' "
                    f"({attempt + 1} attempt(s))."
                ) from None
            except httpx.TransportError as exc:
                if attempt < self._max_retries:
                    await self._backoff(attempt, None)
                    attempt += 1
                    continue
                raise OICError(
                    f"Could not reach {target} at {url.host} for environment '{self.env}' "
                    f"({type(exc).__name__}). Check the URL and network access."
                ) from None
            except httpx.HTTPError as exc:  # e.g. DecodingError: a body we cannot decode
                raise OICError(
                    f"{target} returned an unreadable response for environment '{self.env}' ({type(exc).__name__})."
                ) from None
            if resp.status_code in RETRYABLE_STATUS and attempt < self._max_retries:
                await self._backoff(attempt, resp.headers.get("retry-after"))
                attempt += 1
                continue
            return resp

    # --- auth --------------------------------------------------------------

    async def token(self, *, force: bool = False, stale: str | None = None) -> str:
        """Cached token. `stale` = a token OIC just rejected: refresh only if it is still the
        cached one, so N concurrent 401s cause one refresh, not N."""
        async with self._token_lock:
            now = time.monotonic()
            valid = bool(self._token) and now < self._token_expires
            if valid and not force and (stale is None or self._token != stale):
                return self._token  # type: ignore[return-value]
            data = {
                "grant_type": "client_credentials",
                "client_id": self.cfg.client_id,
                "client_secret": self.cfg.client_secret,
            }
            if self.cfg.scope:
                data["scope"] = self.cfg.scope
            resp = await self._send(
                "POST",
                httpx.URL(self.cfg.token_url),
                target="the IDCS token endpoint",
                max_bytes=MAX_TOKEN_RESPONSE_BYTES,
                data=data,
                headers={"Accept": "application/json"},
            )
            if resp.status_code >= 300:
                raise OICError(self._token_error(resp), status=resp.status_code)
            try:
                payload = resp.json()
            except ValueError:
                raise OICError(
                    f"The token endpoint for '{self.env}' did not return JSON. Check token_url."
                ) from None
            access = payload.get("access_token") if isinstance(payload, dict) else None
            if not access:
                raise OICError(f"The token endpoint for '{self.env}' returned no access_token. Check token_url/scope.")
            try:
                ttl = float(payload.get("expires_in") or 3600)
            except (TypeError, ValueError):
                ttl = 3600.0
            self._token = str(access)
            self._token_expires = now + max(ttl - 60, ttl / 2)
            logger.info("Fetched OAuth token for environment %s", self.env)
            return self._token

    def _token_error(self, resp: httpx.Response) -> str:
        status = resp.status_code
        code, desc = "", ""
        try:
            body = resp.json()
            if isinstance(body, dict):
                code = str(body.get("error") or "")
                desc = str(body.get("error_description") or "")[:200]
        except ValueError:
            pass
        if 300 <= status < 400:
            return (
                f"token_url for '{self.env}' redirected (HTTP {status}). Use the final token URL; "
                "credentials are never sent through redirects."
            )
        if code == "invalid_scope":
            return f"IDCS rejected the scope for '{self.env}' (invalid_scope). Fix or remove 'scope' in the INI."
        if status == 401 or code in ("invalid_client", "unauthorized_client"):
            return (
                f"IDCS rejected the client credentials for environment '{self.env}' "
                f"(HTTP {status}{', ' + code if code else ''}). Check client_id, client_secret and token_url."
            )
        suffix = f", {code}" if code else ""
        return f"Token request for '{self.env}' failed (HTTP {status}{suffix}){': ' + desc if desc else ''}."

    # --- requests ----------------------------------------------------------

    def _url(self, path: str, *, raw: bool = False) -> httpx.URL:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or "\\" in path
            or any(ord(ch) < 0x20 for ch in path)
        ):
            raise OICError("OIC paths must be absolute paths on the OIC host, e.g. /ic/api/integration/v1/integrations")
        if raw and any(tok in path.split("?", 1)[0].lower() for tok in ("%2e", "%2f", "%5c")):
            # the check below sees the decoded path, but the encoded one is what gets sent
            raise OICError("Encoded '.', '/' or '\\' are not allowed in fetch_raw_path paths.")
        url = self._base.join(path)
        if (url.scheme, url.host, url.port) != (self._base.scheme, self._base.host, self._base.port):
            raise OICError("That path resolves to a different host; only the configured OIC host is allowed.")
        if raw and not url.path.startswith("/ic/api/"):
            raise OICError("fetch_raw_path only allows paths under /ic/api/.")
        return url

    def _redirect_allowed(self, url: httpx.URL) -> bool:
        if url.scheme != "https" and not (self._allow_insecure and url.scheme == "http"):
            return False
        host = (url.host or "").lower()
        if host == (self._base.host or "").lower() and url.port == self._base.port:
            return True
        if self._design_host and host == self._design_host and url.port is None:
            return True
        return any(host.endswith(suffix) for suffix in self._suffixes)

    async def _authorized_get(
        self, url: httpx.URL, accept: str, what: str, max_bytes: int | None, *, stale: str | None = None
    ) -> tuple[httpx.Response, str]:
        token = await self.token(stale=stale)
        headers = {"Authorization": f"Bearer {token}", "Accept": accept}
        resp = await self._send("GET", url, target="OIC", max_bytes=max_bytes, headers=headers)
        hops = 0
        while resp.status_code in REDIRECT_STATUS and hops < 5:
            location = resp.headers.get("location")
            if not location:
                break
            nxt = resp.url.join(location)
            if not self._redirect_allowed(nxt):
                raise OICError(
                    f"OIC redirected {what} to an unexpected host ({nxt.host}); refusing to forward credentials. "
                    "If that host is legitimate, add its domain suffix to OIC_REDIRECT_ALLOWED_SUFFIXES."
                )
            resp = await self._send("GET", nxt, target="OIC", max_bytes=max_bytes, headers=headers)
            hops += 1
        return resp, token

    async def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        accept: str = "application/json",
        what: str | None = None,
        raw: bool = False,
        max_bytes: int | None = None,
    ) -> httpx.Response:
        url = self._url(path, raw=raw)
        query = {k: v for k, v in (params or {}).items() if v is not None}
        if self.cfg.instance_name and "integrationInstance" not in url.params:
            query.setdefault("integrationInstance", self.cfg.instance_name)
        if query:
            # merge, don't replace: httpx 0.28's params= would drop a query string already in the path
            url = url.copy_merge_params(query)
        label = what or path
        started = time.monotonic()
        resp, used = await self._authorized_get(url, accept, label, max_bytes)
        if resp.status_code == 401:  # token revoked/rotated server-side: refresh once
            resp, _ = await self._authorized_get(url, accept, label, max_bytes, stale=used)
        logger.info(
            "OIC GET %s env=%s status=%s %.2fs", url.path, self.env, resp.status_code, time.monotonic() - started
        )
        if resp.status_code >= 400:
            raise self._api_error(resp, label)
        if resp.status_code in REDIRECT_STATUS:
            raise OICError(f"OIC kept redirecting {label} (HTTP {resp.status_code}).", status=resp.status_code)
        return resp

    def _api_error(self, resp: httpx.Response, what: str) -> OICError:
        status = resp.status_code
        detail = _error_detail(resp)
        env = self.env
        gen3_hint = ""
        if status in (400, 404) and not self.cfg.instance_name:
            gen3_hint = " If this is an OIC Gen3 instance, set instance_name (the About page 'Service instance') in the INI."
        if status == 401:
            msg = (
                f"OIC rejected the access token for environment '{env}' (HTTP 401) even after a refresh. "
                "The token was issued, so this is usually a missing role: in IDCS/IAM open the OIC instance's own "
                "resource app (not your client app) -> Application roles -> ServiceUser, and assign your "
                f"confidential app. Also confirm integrationInstance ({self.cfg.instance_name or 'not set'})."
            )
        elif status == 403:
            msg = f"OIC refused access to {what} in '{env}' (HTTP 403): the app's role does not permit it."
        elif status == 404:
            msg = f"Not found in '{env}': {what} (HTTP 404).{gen3_hint}"
        elif status == 400:
            msg = f"OIC rejected the request for {what} in '{env}' (HTTP 400){': ' + detail if detail else ''}.{gen3_hint}"
        elif status in RETRYABLE_STATUS:
            msg = f"OIC is unavailable for '{env}' (HTTP {status}) after {self._max_retries + 1} attempt(s). Try again shortly."
        else:
            msg = f"OIC returned HTTP {status} for {what} in '{env}'{': ' + detail if detail else ''}."
        return OICError(msg, status=status)

    async def get_json(self, path: str, params: dict[str, Any] | None = None, *, what: str | None = None) -> Any:
        resp = await self.get(path, params, what=what)
        ctype = resp.headers.get("content-type", "")
        if "json" in ctype:
            try:
                return resp.json()
            except ValueError:
                pass
        return {"contentType": ctype, "text": resp.text[:20000]}

    async def _get_json_fallback(self, paths: list[str], params: dict[str, Any] | None, *, what: str) -> Any:
        """Some tenants expose an endpoint under design/v1 or monitoring/v1 instead."""
        last: OICError | None = None
        for path in paths:
            try:
                return await self.get_json(path, params, what=what)
            except OICError as exc:
                if exc.status != 404:
                    raise
                last = exc
        assert last is not None
        raise last

    async def fetch_raw(self, path: str) -> dict[str, Any]:
        resp = await self.get(path, what=path, raw=True)
        ctype = resp.headers.get("content-type", "")
        if "json" in ctype:
            try:
                return {"contentType": ctype, "json": resp.json()}
            except ValueError:
                pass
        return {"contentType": ctype, "text": resp.text}

    # --- integration catalogue ---------------------------------------------

    async def list_integrations_page(
        self, *, status: str | None, limit: int, offset: int, order_by: str | None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset, "orderBy": order_by, "q": build_q({"status": status})}
        return unwrap(await self.get_json(INTEGRATIONS, params, what="the integration list"))

    async def catalogue(self) -> tuple[list[dict[str, Any]], bool]:
        """All integrations (every version), paged with offset/limit and cached briefly.

        Upstream paged with a 'page' parameter that OIC does not have, so its full scans
        could only ever see the first page.
        """
        async with self._catalogue_lock:
            if self._catalogue is not None and time.monotonic() - self._catalogue_at < self._catalogue_ttl:
                return self._catalogue, self._catalogue_complete
            items: list[dict[str, Any]] = []
            seen: set[str] = set()
            offset, complete = 0, False
            for _ in range(MAX_CATALOGUE_PAGES):
                page = await self.list_integrations_page(status=None, limit=PAGE_SIZE, offset=offset, order_by=None)
                batch = [i for i in as_list(page.get("items")) if isinstance(i, dict)]
                fresh = []
                for item in batch:
                    key = str(item.get("id") or f"{item.get('code')}|{item.get('version')}")
                    if key not in seen:
                        seen.add(key)
                        fresh.append(item)
                items.extend(fresh)
                if not batch or not page.get("hasMore"):
                    complete = True
                    break
                if not fresh:  # server ignored offset; stop rather than loop
                    break
                offset += len(batch)
            self._catalogue, self._catalogue_complete, self._catalogue_at = items, complete, time.monotonic()
            logger.info("Catalogue for %s: %d integration versions (complete=%s)", self.env, len(items), complete)
            return items, complete

    async def resolve(self, identifier: str, version: str | None = None) -> tuple[str, str, str]:
        """Return (code, version, how). Without a version: highest ACTIVATED version, else highest overall."""
        code, ver = split_identifier(identifier, version)
        if ver:
            return code, ver, "as requested"
        items, complete = await self.catalogue()
        matches = [i for i in items if str(i.get("code", "")).upper() == code.upper()]
        if not matches:
            note = "" if complete else " (the catalogue scan was incomplete)"
            raise OICError(
                f"No integration with code '{code}' in environment '{self.env}'{note}. "
                "Use search_integrations to find the right code.",
                status=404,
            )
        activated = [i for i in matches if str(i.get("status", "")).upper() == "ACTIVATED"]
        pool = activated or matches
        best = max(pool, key=lambda i: version_key(str(i.get("version", ""))))
        how = "latest activated version" if activated else "latest version (none activated)"
        return str(best.get("code") or code), str(best.get("version") or ""), how

    async def integration(self, identifier: str, version: str | None = None) -> tuple[Any, dict[str, str]]:
        code, ver, how = await self.resolve(identifier, version)
        key = (code, ver)
        cached = self._design_cache.get(key)
        if cached and time.monotonic() - cached[0] < self._catalogue_ttl:
            data = cached[1]
        else:
            data = await self.get_json(f"{INTEGRATIONS}/{seg(f'{code}|{ver}')}", what=f"integration {code}|{ver}")
            self._design_cache[key] = (time.monotonic(), data)
            while len(self._design_cache) > DESIGN_CACHE_SIZE:
                self._design_cache.popitem(last=False)
        return data, {"code": code, "version": ver, "versionResolution": how}

    async def export_archive(self, identifier: str, version: str | None = None) -> tuple[bytes, str, dict[str, str]]:
        code, ver, how = await self.resolve(identifier, version)
        resp = await self.get(
            f"{INTEGRATIONS}/{seg(f'{code}|{ver}')}/archive",
            accept="application/octet-stream, application/zip",
            what=f"archive of {code}|{ver}",
            max_bytes=MAX_ARCHIVE_BYTES,
        )
        disposition = resp.headers.get("content-disposition", "")
        match = re.search(r'filename="?([^";]+)"?', disposition)
        filename = match.group(1) if match else f"{code}_{ver}.iar"
        return resp.content, filename, {"code": code, "version": ver, "versionResolution": how}

    # --- monitoring --------------------------------------------------------

    @staticmethod
    def _window(timewindow: str | None, start: str | None, end: str | None, *, narrow: bool) -> dict[str, Any]:
        if start or end:
            return {
                "startdate": to_oic_datetime(start) if start else None,
                "enddate": to_oic_datetime(end, end_of_day=True) if end else None,
            }
        if timewindow:
            return {"timewindow": timewindow}
        # OIC defaults to the last hour. When the caller is looking for something specific
        # (an integration or a business ID) search the whole retention period instead.
        return {"timewindow": "RETENTIONPERIOD" if narrow else "1h"}

    async def list_instances(
        self,
        *,
        integration: str | None,
        status: str | None,
        timewindow: str | None,
        start: str | None,
        end: str | None,
        business_id: str | None,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        code, ver = split_identifier(integration) if integration else (None, None)
        filters = self._window(timewindow, start, end, narrow=bool(code or business_id))
        filters.update(code=code, version=ver, status=status, businessIDValue=business_id)
        params = {"q": build_q(filters), "limit": limit, "offset": offset}
        data = await self._get_json_fallback(
            [f"{MONITORING}/instances", "/ic/api/monitoring/v1/instances"], params, what="runtime instances"
        )
        return unwrap(data), {k: v for k, v in filters.items() if v is not None}

    async def list_errors(
        self,
        *,
        integration: str | None,
        timewindow: str | None,
        start: str | None,
        end: str | None,
        business_id: str | None,
        error_text: str | None,
        recoverable: bool | None,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        code, ver = split_identifier(integration) if integration else (None, None)
        filters = self._window(timewindow, start, end, narrow=bool(code or business_id or error_text))
        filters.update(
            code=code,
            version=ver,
            businessIDValue=business_id,
            errorMessage=error_text,
            recoverable=None if recoverable is None else str(recoverable).lower(),
        )
        params = {"q": build_q(filters), "limit": limit, "offset": offset}
        data = await self._get_json_fallback(
            [f"{MONITORING}/errors", "/ic/api/monitoring/v1/errors"], params, what="errored instances"
        )
        return unwrap(data), {k: v for k, v in filters.items() if v is not None}

    async def instance(self, instance_id: str) -> Any:
        return await self._get_json_fallback(
            [f"{MONITORING}/instances/{seg(instance_id)}", f"/ic/api/monitoring/v1/instances/{seg(instance_id)}"],
            None,
            what=f"runtime instance {instance_id}",
        )

    async def activity_stream(self, instance_id: str, tz: str | None) -> Any:
        # activityStreamDetails is current; activityStream is deprecated but still on older tenants.
        return await self._get_json_fallback(
            [
                f"{MONITORING}/instances/{seg(instance_id)}/activityStreamDetails",
                f"{MONITORING}/instances/{seg(instance_id)}/activityStream",
            ],
            {"timezone": tz},
            what=f"activity stream of instance {instance_id}",
        )

    async def history(
        self, *, frequency: str, timewindow: str | None, start: str | None, end: str | None
    ) -> tuple[Any, dict[str, Any]]:
        filters: dict[str, Any] = {}
        if start or end:
            filters = self._window(None, start, end, narrow=False)
        elif timewindow:
            filters = {"timewindow": timewindow}
        params = {"frequency": frequency, "q": build_q(filters)}
        data = await self.get_json(f"{MONITORING}/history", params, what="historical metrics")
        return data, {"frequency": frequency, **{k: v for k, v in filters.items() if v is not None}}

    async def message_summary(self) -> Any:
        return await self.get_json(f"{MONITORING}/integrations/messages/summary", what="message count summary")

    async def schedule(self, identifier: str, version: str | None = None) -> tuple[Any, dict[str, str]]:
        code, ver, how = await self.resolve(identifier, version)
        try:
            data = await self.get_json(f"{INTEGRATIONS}/{seg(f'{code}|{ver}')}/schedule", what=f"schedule of {code}|{ver}")
        except OICError as exc:
            if exc.status == 404:
                raise OICError(
                    f"No schedule for {code}|{ver} in '{self.env}' (it may not be a scheduled integration).",
                    status=404,
                ) from None
            raise
        return data, {"code": code, "version": ver, "versionResolution": how}

    async def schedules(self, *, status: str | None, limit: int) -> dict[str, Any]:
        items, complete = await self.catalogue()
        scheduled_known = any("style" in i for i in items)
        candidates = [
            i
            for i in items
            if (not status or str(i.get("status", "")).upper() == status)
            and (not scheduled_known or str(i.get("style", "")).lower() == "freeform_scheduled")
        ]
        candidates.sort(key=lambda i: (str(i.get("code")), version_key(str(i.get("version", "")))))
        checked = candidates[:limit]
        sem = asyncio.Semaphore(SCHEDULE_CONCURRENCY)

        async def one(item: dict[str, Any]) -> tuple[dict[str, Any], Any, str | None]:
            async with sem:
                try:
                    data, _ = await self.schedule(str(item.get("code")), str(item.get("version")))
                    return item, data, None
                except OICError as exc:
                    return item, None, (None if exc.status == 404 else str(exc))

        results = await asyncio.gather(*(one(i) for i in checked))
        found, errors = [], []
        for item, data, error in results:
            ident = {"code": item.get("code"), "version": item.get("version"), "name": item.get("name")}
            if error:
                errors.append({**ident, "error": error})
            elif data is not None:
                found.append({**ident, "schedule": data})
        return {
            "items": found,
            "checkedIntegrations": len(checked),
            "matchingIntegrations": len(candidates),
            "filteredByStyle": scheduled_known,
            "catalogueComplete": complete,
            "errors": errors,
        }

    # --- building blocks ---------------------------------------------------

    async def connections(self, *, limit: int, offset: int) -> Any:
        return unwrap(await self.get_json("/ic/api/integration/v1/connections", {"limit": limit, "offset": offset}, what="connections"))

    async def connection(self, identifier: str) -> Any:
        return await self.get_json(f"/ic/api/integration/v1/connections/{seg(identifier)}", what=f"connection {identifier}")

    async def packages(self, *, limit: int, offset: int) -> Any:
        params = {"limit": limit, "offset": offset}
        return unwrap(
            await self._get_json_fallback(
                ["/ic/api/integration/v1/packages", "/ic/api/design/v1/packages"], params, what="packages"
            )
        )

    async def package(self, name: str) -> Any:
        return await self._get_json_fallback(
            [f"/ic/api/integration/v1/packages/{seg(name)}", f"/ic/api/design/v1/packages/{seg(name)}"],
            None,
            what=f"package {name}",
        )

    async def lookups(self, *, limit: int, offset: int) -> Any:
        return unwrap(await self.get_json("/ic/api/integration/v1/lookups", {"limit": limit, "offset": offset}, what="lookups"))

    async def lookup(self, name: str) -> Any:
        return await self._get_json_fallback(
            [f"/ic/api/integration/v1/lookups/{seg(name)}", f"/ic/api/design/v1/lookups/{seg(name)}"],
            None,
            what=f"lookup {name}",
        )

    async def libraries(self, *, limit: int, offset: int) -> Any:
        params = {"limit": limit, "offset": offset}
        return unwrap(
            await self._get_json_fallback(
                ["/ic/api/integration/v1/libraries", "/ic/api/design/v1/libraries"], params, what="libraries"
            )
        )

    async def library(self, name: str) -> Any:
        return await self._get_json_fallback(
            [f"/ic/api/integration/v1/libraries/{seg(name)}", f"/ic/api/design/v1/libraries/{seg(name)}"],
            None,
            what=f"library {name}",
        )

    async def adapters(self) -> Any:
        return unwrap(await self.get_json("/ic/api/integration/v1/adapters", what="adapters"))

    async def adapter(self, name: str) -> Any:
        return await self.get_json(f"/ic/api/integration/v1/adapters/{seg(name)}", what=f"adapter {name}")

    async def agent_groups(self) -> Any:
        return unwrap(await self.get_json(f"{MONITORING}/agentgroups", what="agent groups"))

    async def agents(self) -> dict[str, Any]:
        groups = as_list((await self.agent_groups()).get("items"))
        ids = [str(g.get("id") or g.get("agentGroupCode")) for g in groups if isinstance(g, dict) and (g.get("id") or g.get("agentGroupCode"))]

        async def one(group_id: str) -> tuple[str, Any, str | None]:
            try:
                data = await self.get_json(f"{MONITORING}/agentgroups/{seg(group_id)}/agents", what=f"agents of group {group_id}")
                return group_id, as_list(unwrap(data).get("items")), None
            except OICError as exc:
                return group_id, [], str(exc)

        agents: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for group_id, items, error in await asyncio.gather(*(one(g) for g in ids)):
            if error:
                errors.append({"agentGroup": group_id, "error": error})
            for agent in items:
                if isinstance(agent, dict):
                    agents.append({**agent, "agentGroupId": group_id})
        return {"items": agents, "agentGroups": len(ids), "errors": errors}


def archive_listing(content: bytes, *, preview_bytes: int, max_entries: int) -> dict[str, Any]:
    """List (and optionally preview) entries of an exported archive without extracting it."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        return {"entries": [], "note": "The archive is not a readable zip file."}
    entries: list[dict[str, Any]] = []
    infos = archive.infolist()
    for info in infos[:max_entries]:
        entry: dict[str, Any] = {"name": info.filename, "size": info.file_size}
        if preview_bytes and not info.is_dir() and info.file_size <= preview_bytes:
            try:
                entry["textPreview"] = archive.read(info).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - corrupt/odd entry: list it without a preview
                entry["previewError"] = "unreadable entry"
        entries.append(entry)
    return {"entries": entries, "totalEntries": len(infos), "entriesShown": len(entries)}
