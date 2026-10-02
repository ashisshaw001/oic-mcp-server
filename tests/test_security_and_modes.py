"""Startup refusals, Host allowlist, loopback-only dev mode, and the stateless transport."""

from __future__ import annotations

import httpx
import pytest

from oic_mcp.app import create_app
from oic_mcp.config_parser import parse_ini
from oic_mcp.settings import Settings
from tests.conftest import ServerThread, free_port
from tests.test_e2e import TOKEN, call, connect, env_block


def settings(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({}, "No MCP_AUTH_TOKENS"),
        ({"mcp_auth_tokens": "short"}, "at least 16"),
        ({"mcp_auth_disabled": True, "mcp_host": "0.0.0.0"}, "only allowed when MCP_HOST is a loopback"),
    ],
)
def test_refuses_to_start_unsafely(kw, message):
    with pytest.raises(RuntimeError, match=message):
        create_app(settings(**kw), server_environments={})


def test_unknown_env_keys_do_not_crash_startup(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(f"MCP_AUTH_TOKENS={TOKEN}\nMCP_LOG_FILE=server.log\nSOMETHING_ELSE=1\n")
    loaded = Settings(_env_file=str(env_file))  # upstream crashed here (extra_forbidden)
    assert loaded.mcp_log_file == "server.log"


async def asgi_get(app, path: str, headers: dict[str, str]) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://placeholder") as http:
        return await http.get(path, headers=headers)


async def asgi(app, method: str, path: str, headers: dict[str, str]) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://placeholder") as http:
        return await http.request(method, path, headers=headers)


async def test_host_allowlist_protects_everything_but_healthz():
    app = create_app(settings(mcp_auth_tokens=TOKEN, mcp_allowed_hosts="mcp.example.com"), server_environments={})
    auth = {"Authorization": f"Bearer {TOKEN}"}
    assert (await asgi(app, "POST", "/config", {"Host": "attacker.example", **auth})).status_code == 421
    assert (await asgi(app, "POST", "/config", {"Host": "mcp.example.com", **auth})).status_code == 400  # empty INI
    # probes use internal Host headers (Docker HEALTHCHECK: 127.0.0.1:8080) and must keep working
    assert (await asgi(app, "GET", "/healthz", {"Host": "127.0.0.1:8080"})).status_code == 200
    assert (await asgi(app, "HEAD", "/healthz", {"Host": "127.0.0.1:8080"})).status_code == 200


async def test_auth_disabled_only_accepts_local_host_headers():
    app = create_app(settings(mcp_auth_disabled=True), server_environments={})
    assert (await asgi(app, "POST", "/config", {"Host": "127.0.0.1:8085"})).status_code == 400  # reached the app
    # a DNS-rebinding page would arrive with its own hostname
    assert (await asgi(app, "POST", "/config", {"Host": "rebind.attacker.example:8085"})).status_code == 421


async def test_stateless_transport_cannot_remember_selection_even_with_a_session_header(mock_oic):
    ini = env_block("prod", mock_oic.url, "prod-client", "s-XYZ") + env_block("dev", mock_oic.url, "dev-client", "d-XYZ")
    app = create_app(
        settings(mcp_auth_tokens=TOKEN, allow_insecure_oic_urls=True, mcp_stateless=True),
        server_environments=parse_ini(ini, allow_insecure=True),
    )
    with ServerThread(app, free_port()) as server:
        async with connect(server, mode="legacy", headers={"Mcp-Session-Id": "made-up-123"}) as client:
            err, sel = await call(client, "select_oic_environment", environment="dev")
            assert not err and sel["remembered"] is False
            assert not app.state.registry._sessions  # a forged id creates no state
            err, found = await call(client, "search_integrations", environment="dev")
            assert not err and found["items"][0]["code"] == "DEV_ONLY_FLOW"


async def test_unexpected_exceptions_reach_the_model_as_a_readable_error(monkeypatch):
    from mcp.server.mcpserver.exceptions import ToolError

    from oic_mcp.oic_client import OICClient

    ini = "[prod]\nurl=https://p.example.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.example.com"
    app = create_app(settings(mcp_auth_tokens=TOKEN), server_environments=parse_ini(ini))

    async def broken(self):
        raise TypeError("unexpected shape")

    monkeypatch.setattr(OICClient, "message_summary", broken)
    with pytest.raises(ToolError) as info:
        await app.state.mcp.call_tool("get_message_summary", {})
    assert "get_message_summary failed unexpectedly (TypeError)" in str(info.value)
