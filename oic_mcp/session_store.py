"""Which OIC environment does a tool call use?

Config sources, checked in this order for each call:
  1. X-OIC-Config-Id request header     - a HARD scope set by a trusted backend (e.g. the chat
                                          API) per user: only that config's environments are
                                          reachable, and results show bare names, so the model
                                          never sees the config_id
  2. environment="<config_id>/<name>"  - an uploaded config, addressed explicitly
     environment="server/<name>"       - the server-side config, addressed explicitly
  3. use_oic_config() on this session   - legacy MCP sessions only
  4. the server-side INI (OIC_CONFIG_FILE)

Within that config the environment is: the explicit name, else the one selected for this
MCP session, else the only one. With several and no choice, the call fails with the list so
the model can ask the user (the agreed behaviour).

Isolation:
* Uploaded configs and session state belong to the caller's principal: a hash of the Bearer
  token used. Give each tenant/backend its own token (MCP_AUTH_TOKENS accepts several) and
  they cannot see, use, delete or evict each other's uploads or sessions. Callers sharing one
  token share a principal, so a config_id or session id is then a capability: it never
  appears in logs or error messages, and the header path keeps it away from the model.
* Session ids are only used when the MCP SDK has validated them (stateful transport, a
  handshake-era protocol). MCP 2026-07-28 requests have no session; the SDK does not check
  an Mcp-Session-Id header on them, so the tool layer passes session_id=None for those.

Everything here is in memory, per process. Uploaded credentials are never written to disk.
With more than one replica, use sticky routing on Mcp-Session-Id or pass `environment`.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections import Counter, OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from .config_parser import InstanceConfig
from .oic_client import OICClient, OICError
from .settings import Settings

logger = logging.getLogger(__name__)

SERVER_SOURCE = ""  # client-cache / selection key for the server-side config
SERVER_PREFIX = "server"  # environment="server/<name>"
SWEEP_INTERVAL_SECS = 60.0
MAX_SESSIONS = 10000
MAX_UPLOAD_CLIENTS_PER_OWNER = 50
MAX_UPLOAD_CLIENTS = 1000  # global backstop; server-config clients are never evicted
MAX_LISTED = 20


@dataclass
class UploadedConfig:
    config_id: str
    owner: str
    environments: dict[str, InstanceConfig]
    created: float
    last_used: float


@dataclass
class SessionState:
    last_used: float
    config_id: str | None = None
    selected: str | None = None
    selected_source: str | None = None  # config_id the selection belongs to ("" = server config)


@dataclass(frozen=True)
class Resolved:
    source: str  # "server" or "upload"
    config_id: str | None
    name: str
    cfg: InstanceConfig = field(repr=False)
    via_header: bool = False

    @property
    def ref(self) -> str:
        """How results name the environment. Header-scoped calls show the bare name."""
        if self.config_id and not self.via_header:
            return f"{self.config_id}/{self.name}"
        return self.name


def _names(catalog: dict[str, InstanceConfig]) -> str:
    """Environment names for error messages - never config ids (the SDK logs tool errors)."""
    names = list(catalog)
    shown = ", ".join(names[:MAX_LISTED])
    return shown + (f" and {len(names) - MAX_LISTED} more" if len(names) > MAX_LISTED else "")


class Registry:
    def __init__(
        self,
        settings: Settings,
        server_environments: dict[str, InstanceConfig] | None = None,
        *,
        transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
    ) -> None:
        self.settings = settings
        self.server_environments = dict(server_environments or {})
        self._transport_factory = transport_factory
        self._uploads: dict[str, UploadedConfig] = {}
        self._sessions: dict[tuple[str, str], SessionState] = {}
        self._server_clients: dict[str, OICClient] = {}
        self._upload_clients: OrderedDict[tuple[str, str], OICClient] = OrderedDict()
        self._last_sweep = time.monotonic()

    # --- uploaded configs --------------------------------------------------

    def add_upload(self, environments: dict[str, InstanceConfig], owner: str) -> UploadedConfig:
        now = time.monotonic()
        mine = sorted((u for u in self._uploads.values() if u.owner == owner), key=lambda u: u.last_used)
        while len(mine) >= self.settings.oic_max_uploads_per_token:
            self._drop_upload(mine.pop(0).config_id)  # a token only ever evicts its own uploads...
        while len(self._uploads) >= self.settings.oic_max_uploaded_configs:
            # ...unless the server-wide cap is hit: then the heaviest user(s) lose their least
            # recently used upload
            counts = Counter(u.owner for u in self._uploads.values())
            top = max(counts.values())
            victim = min((u for u in self._uploads.values() if counts[u.owner] == top), key=lambda u: u.last_used)
            self._drop_upload(victim.config_id)
        config_id = "cfg_" + secrets.token_urlsafe(18)
        upload = UploadedConfig(config_id, owner, dict(environments), now, now)
        self._uploads[config_id] = upload
        logger.info("Stored uploaded config %s… with %d environment(s)", config_id[:8], len(environments))
        return upload

    def get_upload(self, config_id: str, owner: str) -> UploadedConfig | None:
        """None when unknown, expired, or owned by another principal (indistinguishable on purpose)."""
        upload = self._uploads.get(config_id)
        if upload is None or not secrets.compare_digest(upload.owner, owner):
            return None
        now = time.monotonic()
        if now - upload.last_used > self.settings.oic_upload_ttl_secs:
            self._drop_upload(config_id)
            return None
        upload.last_used = now
        return upload

    def delete_upload(self, config_id: str, owner: str) -> bool:
        if self.get_upload(config_id, owner) is None:
            return False
        self._drop_upload(config_id)
        return True

    def _drop_upload(self, config_id: str) -> None:
        self._uploads.pop(config_id, None)
        for key in [k for k in self._upload_clients if k[0] == config_id]:
            self._upload_clients.pop(key).retire()
        for state in self._sessions.values():
            if state.config_id == config_id:
                state.config_id = None
            if state.selected_source == config_id:
                state.selected, state.selected_source = None, None

    @staticmethod
    def _unknown_config(config_id: str) -> OICError:
        return OICError(
            f"Config '{config_id[:8]}…' is unknown or has expired. Upload the INI file again (POST /config)."
        )

    # --- sessions ----------------------------------------------------------

    def session(self, owner: str, session_id: str | None) -> SessionState | None:
        if not session_id:
            return None
        key = (owner, session_id)
        now = time.monotonic()
        state = self._sessions.get(key)
        if state is None:
            if len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda k: self._sessions[k].last_used)
                self._sessions.pop(oldest, None)
            state = SessionState(last_used=now)
            self._sessions[key] = state
        state.last_used = now
        return state

    # --- resolution --------------------------------------------------------

    def _catalog(self, config_id: str | None, owner: str) -> tuple[str, dict[str, InstanceConfig]]:
        if config_id:
            upload = self.get_upload(config_id, owner)
            if upload is None:
                raise self._unknown_config(config_id)
            return "upload", upload.environments
        if not self.server_environments:
            raise OICError(
                "No OIC environments are configured. Upload an INI file (POST /config) and pass its "
                "config_id, or set OIC_CONFIG_FILE on the server."
            )
        return "server", self.server_environments

    def active_config_id(self, owner: str, session_id: str | None, header_config_id: str | None) -> str | None:
        if header_config_id and header_config_id.strip():
            return header_config_id.strip()
        state = self._sessions.get((owner, session_id)) if session_id else None
        return state.config_id if state else None

    async def resolve(
        self, environment: str | None, *, owner: str, session_id: str | None, header_config_id: str | None
    ) -> Resolved:
        await self._maybe_sweep()
        header = (header_config_id or "").strip() or None
        state = self.session(owner, session_id)
        explicit_source = False
        config_id: str | None = None
        name: str | None = None
        if environment and environment.strip():
            ref = environment.strip()
            if "/" in ref:
                prefix, name = (part.strip() for part in ref.split("/", 1))
                if not prefix or not name:
                    raise OICError(
                        f"Invalid environment {environment[:80]!r}: use a name like 'prod', "
                        "'<config_id>/<name>' for an uploaded config, or 'server/<name>'."
                    )
                explicit_source = True
                config_id = None if prefix == SERVER_PREFIX else prefix
            else:
                name = ref
        if header:
            # The backend scoped this request to one config; nothing else is reachable.
            if explicit_source and config_id != header:
                raise OICError("This request is limited to one uploaded config; pass just the environment name.")
            config_id = header
        elif not explicit_source:
            config_id = self.active_config_id(owner, session_id, None)
        source, catalog = self._catalog(config_id, owner)
        source_key = config_id or SERVER_SOURCE

        if not name and state and state.selected and state.selected_source == source_key:
            name = state.selected
        if not name:
            if len(catalog) == 1:
                name = next(iter(catalog))
            else:
                raise OICError(
                    f"Several OIC environments are configured ({_names(catalog)}). Ask the user which one to "
                    "use, then pass it as `environment` on each call (or call select_oic_environment)."
                )
        key = name.strip().lower()
        if key not in catalog:
            hint = ""
            if source == "upload" and not header and key in self.server_environments:
                hint = f" The server's own '{key}' is reachable as 'server/{key}'."
            raise OICError(f"Unknown environment '{name[:64]}'. Available: {_names(catalog)}.{hint}")
        return Resolved(source=source, config_id=config_id, name=key, cfg=catalog[key], via_header=header is not None)

    @staticmethod
    def refs(config_id: str | None, catalog: dict[str, InstanceConfig]) -> list[str]:
        return [f"{config_id}/{n}" if config_id else n for n in catalog]

    def select(self, owner: str, session_id: str | None, resolved: Resolved) -> bool:
        state = self.session(owner, session_id)
        if state is None:
            return False
        if not resolved.via_header:
            # selecting an uploaded environment makes its config the session's; selecting a
            # server environment explicitly detaches any uploaded one
            state.config_id = resolved.config_id
        state.selected = resolved.name
        state.selected_source = resolved.config_id or SERVER_SOURCE
        return True

    def attach_config(self, owner: str, session_id: str | None, config_id: str) -> bool:
        state = self.session(owner, session_id)
        if state is None:
            return False
        if state.config_id != config_id:
            state.selected, state.selected_source = None, None
        state.config_id = config_id
        return True

    def listing(self, owner: str, session_id: str | None, header_config_id: str | None) -> dict[str, object]:
        header = (header_config_id or "").strip() or None
        config_id = self.active_config_id(owner, session_id, header)
        source, catalog = self._catalog(config_id, owner)
        state = self._sessions.get((owner, session_id)) if session_id else None
        source_key = config_id or SERVER_SOURCE
        selected = state.selected if state and state.selected_source == source_key else None
        shown_id = None if header else config_id
        return {
            "configSource": source,
            "configId": shown_id,
            "environments": [
                {"environment": ref, **cfg.public_view(), "selected": cfg.name == selected}
                for ref, cfg in zip(self.refs(shown_id, catalog), catalog.values())
            ],
            "serverEnvironmentsAlsoAvailable": bool(source == "upload" and not header and self.server_environments),
            "sessionSelectionAvailable": state is not None,
        }

    # --- clients -----------------------------------------------------------

    def _new_client(self, cfg: InstanceConfig) -> OICClient:
        s = self.settings
        return OICClient(
            cfg,
            timeout=s.http_timeout_secs,
            max_retries=s.http_max_retries,
            redirect_suffixes=s.redirect_suffixes,
            catalogue_ttl=s.catalogue_ttl_secs,
            allow_insecure=s.allow_insecure_oic_urls,
            max_response_bytes=s.max_response_bytes,
            transport=self._transport_factory() if self._transport_factory else None,
        )

    def client_for(self, resolved: Resolved) -> OICClient:
        if resolved.config_id is None:  # server config: bounded by the admin's INI, never evicted
            client = self._server_clients.get(resolved.name)
            if client is None or client.cfg is not resolved.cfg:
                if client is not None:
                    client.retire()
                client = self._server_clients[resolved.name] = self._new_client(resolved.cfg)
            return client

        key = (resolved.config_id, resolved.name)
        client = self._upload_clients.get(key)
        if client is not None and client.cfg is resolved.cfg:
            self._upload_clients.move_to_end(key)
            return client
        if client is not None:
            self._upload_clients.pop(key).retire()
        owner = self._uploads[resolved.config_id].owner if resolved.config_id in self._uploads else ""
        mine = [k for k in self._upload_clients if self._owner_of(k[0]) == owner]
        while len(mine) >= MAX_UPLOAD_CLIENTS_PER_OWNER:  # evict this owner's least recent first
            self._upload_clients.pop(mine.pop(0)).retire()
        while len(self._upload_clients) >= MAX_UPLOAD_CLIENTS:
            _, evicted = self._upload_clients.popitem(last=False)
            evicted.retire()
        client = self._upload_clients[key] = self._new_client(resolved.cfg)
        return client

    def _owner_of(self, config_id: str) -> str | None:
        upload = self._uploads.get(config_id)
        return upload.owner if upload else None

    # --- housekeeping ------------------------------------------------------

    async def _maybe_sweep(self) -> None:
        now = time.monotonic()
        if now - self._last_sweep < SWEEP_INTERVAL_SECS:
            return
        self._last_sweep = now
        ttl = self.settings.oic_upload_ttl_secs
        for config_id in [c for c, u in self._uploads.items() if now - u.last_used > ttl]:
            self._drop_upload(config_id)
        idle = self.settings.mcp_session_idle_timeout_secs
        for key in [k for k, st in self._sessions.items() if now - st.last_used > idle]:
            self._sessions.pop(key, None)

    async def aclose(self) -> None:
        clients = [*self._server_clients.values(), *self._upload_clients.values()]
        self._server_clients, self._upload_clients = {}, OrderedDict()
        await asyncio.gather(*(c.aclose() for c in clients), return_exceptions=True)
