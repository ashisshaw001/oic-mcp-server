"""ASGI app: FastAPI outer app (health, config upload) + MCP Streamable HTTP at /mcp."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from . import __version__
from .config_parser import ConfigError, InstanceConfig, load_ini_file, parse_ini
from .security import SecurityMiddleware, principal_of
from .session_store import Registry
from .settings import Settings
from .tools import INSTRUCTIONS, register_tools

logger = logging.getLogger("oic_mcp")


def configure_logging(settings: Settings) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if settings.mcp_log_file:
        handlers.append(RotatingFileHandler(settings.mcp_log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"))
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    # httpx logs full request URLs at INFO; keep it quiet (no secrets there, just noise).
    logging.getLogger("httpx").setLevel(logging.WARNING)


def quiet_session_id_logs() -> None:
    # The SDK logs MCP session ids at INFO ("Created new transport with session ID ...").
    # A session id plus a shared bearer token is enough to use that session, so keep them out of
    # logs. Done in create_app so it holds however the app is launched (uvicorn --factory, etc.).
    for name in ("mcp.server.streamable_http_manager", "mcp.server.streamable_http"):
        logger_ = logging.getLogger(name)
        if logger_.getEffectiveLevel() < logging.WARNING:
            logger_.setLevel(logging.WARNING)


async def _read_capped(request: Request, limit: int) -> bytes | None:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        return None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            return None
    return bytes(body)


def create_app(
    settings: Settings | None = None,
    *,
    server_environments: dict[str, InstanceConfig] | None = None,
    transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
) -> FastAPI:
    settings = settings or Settings()
    settings.check_security()
    quiet_session_id_logs()

    if server_environments is None:
        server_environments = {}
        if settings.oic_config_file:
            server_environments = load_ini_file(settings.oic_config_file, allow_insecure=settings.allow_insecure_oic_urls)
    registry = Registry(settings, server_environments, transport_factory=transport_factory)

    mcp = MCPServer(name="oic-monitoring", version=__version__, instructions=INSTRUCTIONS)
    register_tools(mcp, registry, settings)
    mcp_app = mcp.streamable_http_app(
        streamable_http_path=settings.mcp_path,
        json_response=settings.mcp_json_response,
        stateless_http=settings.mcp_stateless,
        session_idle_timeout=float(settings.mcp_session_idle_timeout_secs),
        # Host/Origin checks are done by SecurityMiddleware for the whole app.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # A mounted Starlette app's own lifespan does not run, so start the MCP session manager here.
        async with mcp.session_manager.run():
            logger.info(
                "OIC MCP server %s ready: %d server-side environment(s), uploads %s, %s transport",
                __version__,
                len(server_environments),
                "enabled" if settings.oic_config_uploads_enabled else "disabled",
                "stateless" if settings.mcp_stateless else "stateful",
            )
            yield
        await registry.aclose()

    app = FastAPI(title="OIC Monitoring MCP", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.registry = registry
    app.state.mcp = mcp

    @app.api_route("/healthz", methods=["GET", "HEAD"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/config")
    async def upload_config(request: Request) -> Response:
        """Upload an INI file (raw body). Returns a config_id; credentials stay server-side, in memory."""
        if not settings.oic_config_uploads_enabled:
            return JSONResponse({"error": "Config uploads are disabled on this server."}, status_code=404)
        body = await _read_capped(request, settings.oic_max_upload_bytes)
        if body is None:
            return JSONResponse({"error": f"Config file larger than {settings.oic_max_upload_bytes} bytes."}, status_code=413)
        try:
            text = body.decode("utf-8-sig")
        except UnicodeDecodeError:
            return JSONResponse({"error": "Config must be UTF-8 text (an INI file)."}, status_code=400)
        try:
            environments = parse_ini(
                text,
                allow_insecure=settings.allow_insecure_oic_urls,
                max_environments=settings.oic_max_environments_per_upload,
                allowed_host_suffixes=settings.upload_host_suffixes,
            )
        except ConfigError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        upload = registry.add_upload(environments, owner=principal_of(request.headers.get("authorization")))
        return JSONResponse(
            {
                "config_id": upload.config_id,
                "expires_after_idle_secs": settings.oic_upload_ttl_secs,
                "environments": [
                    {"environment": ref, **cfg.public_view()}
                    for ref, cfg in zip(registry.refs(upload.config_id, environments), environments.values())
                ],
                "usage": "Send header X-OIC-Config-Id: <config_id> on MCP requests, call use_oic_config, "
                "or pass environment='<config_id>/<name>' to tools.",
            },
            status_code=201,
        )

    @app.delete("/config/{config_id}")
    async def delete_config(config_id: str, request: Request) -> Response:
        if registry.delete_upload(config_id, owner=principal_of(request.headers.get("authorization"))):
            return Response(status_code=204)
        return JSONResponse({"error": "Unknown or expired config_id."}, status_code=404)

    app.mount("/", mcp_app)  # serves settings.mcp_path (default /mcp)
    app.add_middleware(SecurityMiddleware, settings=settings)
    return app


def main() -> None:
    import uvicorn

    settings = Settings()
    configure_logging(settings)
    try:
        app = create_app(settings)
    except (ConfigError, RuntimeError) as exc:
        raise SystemExit(f"oic-mcp: {exc}") from None
    uvicorn.run(app, host=settings.mcp_host, port=settings.mcp_port, log_level=settings.log_level.lower(), proxy_headers=True)
