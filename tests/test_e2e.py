"""End to end: real HTTP, the MCP SDK's own client, our app, and a fake OIC/IDCS.

Covers both protocol eras: 'legacy' (initialize handshake + Mcp-Session-Id) and the
2026-07-28 'modern' protocol (self-contained requests, no session).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager

import httpx
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from oic_mcp.app import create_app
from oic_mcp.config_parser import parse_ini
from oic_mcp.settings import Settings
from tests.conftest import ServerThread, free_port

TOKEN = "e2e-token-0123456789abcdef-XYZ"
TOKEN_B = "e2e-other-tenant-token-9876543210"
SECRETS = ("prod-secret-XYZ", "dev-secret-XYZ", "norole-secret-XYZ")


def env_block(name: str, base: str, client: str, secret: str, extra: str = "") -> str:
    return (
        f"[{name}]\nurl = {base}\nclient_id = {client}\nclient_secret = {secret}\n"
        f"token_url = {base}/oauth2/v1/token\n{extra}\n"
    )


@pytest.fixture(scope="module")
def server(mock_oic) -> Iterator[ServerThread]:
    base = mock_oic.url
    ini = (
        env_block("prod", base, "prod-client", SECRETS[0], "instance_name = prodinst")
        + env_block("dev", base, "dev-client", SECRETS[1])
        + env_block("norole", base, "norole-client", SECRETS[2])
        + env_block("badsecret", base, "prod-client", "wrong")
    )
    settings = Settings(
        _env_file=None,
        mcp_auth_tokens=f"{TOKEN},{TOKEN_B}",
        allow_insecure_oic_urls=True,
        oic_upload_allowed_host_suffixes="",  # the fake OIC lives on 127.0.0.1
        mcp_allowed_origins="https://allowed.example",
        http_max_retries=0,
    )
    app = create_app(settings, server_environments=parse_ini(ini, allow_insecure=True))
    with ServerThread(app, free_port()) as srv:
        yield srv


@asynccontextmanager
async def connect(
    server: ServerThread, *, mode: str = "legacy", headers: dict[str, str] | None = None, token: str = TOKEN
) -> AsyncIterator[Client]:
    all_headers = {"Authorization": f"Bearer {token}", **(headers or {})}
    async with create_mcp_http_client(headers=all_headers) as http:
        async with Client(streamable_http_client(f"{server.url}/mcp", http_client=http), mode=mode) as client:
            yield client


async def call(client: Client, name: str, **arguments) -> tuple[bool, dict | str]:
    result = await client.call_tool(name, arguments)
    text = result.content[0].text if result.content else ""
    try:
        return bool(result.is_error), json.loads(text)
    except json.JSONDecodeError:
        return bool(result.is_error), text


# --- HTTP-level security -------------------------------------------------------------------


def test_healthz_open_everything_else_needs_the_bearer(server):
    with httpx.Client(base_url=server.url) as http:
        assert http.get("/healthz").json() == {"status": "ok"}
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        no_auth = http.post("/mcp", json=body)
        assert no_auth.status_code == 401 and "bearer" in no_auth.headers["www-authenticate"].lower()
        assert http.post("/mcp", json=body, headers={"Authorization": "Bearer wrong-token-0123456789"}).status_code == 401
        assert http.post("/config", content="[x]").status_code == 401
        evil = http.post("/mcp", json=body, headers={"Authorization": f"Bearer {TOKEN}", "Origin": "https://evil.example"})
        assert evil.status_code == 403


# --- protocol eras & environment selection ---------------------------------------------------


async def test_legacy_session_can_select_an_environment(server):
    async with connect(server, mode="legacy") as client:
        tools = await client.list_tools()
        assert len(tools.tools) == 36

        err, text = await call(client, "search_integrations", query="order")
        assert err and "Several OIC environments" in text and "prod" in text

        err, listing = await call(client, "list_oic_environments")
        assert not err and [e["environment"] for e in listing["environments"]] == ["prod", "dev", "norole", "badsecret"]
        assert listing["sessionSelectionAvailable"] is True
        assert not any(s in json.dumps(listing) for s in SECRETS)

        err, dev = await call(client, "search_integrations", environment="dev")
        assert not err and dev["environment"] == "dev" and [i["code"] for i in dev["items"]] == ["DEV_ONLY_FLOW"]

        err, sel = await call(client, "select_oic_environment", environment="prod")
        assert not err and sel["remembered"] is True

        err, prod = await call(client, "search_integrations", query="order")
        assert not err and prod["environment"] == "prod"
        assert prod["catalogueSize"] == 154 and prod["catalogueComplete"]  # paged across 2 x 100
        assert {i["code"] for i in prod["items"]} == {"ORDER_SYNC"}


async def test_modern_protocol_has_no_session_but_explicit_environment_works(server):
    async with connect(server, mode="auto") as client:
        assert client.protocol_version == "2026-07-28"
        err, sel = await call(client, "select_oic_environment", environment="prod")
        assert not err and sel["remembered"] is False and "environment='prod'" in sel["note"]

        err, integ = await call(client, "get_integration", identifier="ORDER_SYNC", environment="prod")
        assert not err
        assert integ["version"] == "02.00.0000" and integ["versionResolution"] == "latest activated version"
        assert "links" not in integ["integration"]


# --- monitoring & design tools ------------------------------------------------------------------


async def test_monitoring_and_design_tools(server, mock_oic):
    httpx.post(f"{mock_oic.url}/_reset")
    async with connect(server, mode="auto") as client:
        err, inst = await call(client, "list_instances", environment="prod", integration="ORDER_SYNC", status="FAILED")
        assert not err and inst["filter"] == {"timewindow": "RETENTIONPERIOD", "code": "ORDER_SYNC", "status": "FAILED"}
        assert len(inst["items"]) == 2 and "links" not in inst["items"][0]

        state = httpx.get(f"{mock_oic.url}/_state").json()
        monitoring = [r for r in state["requests"] if r["path"].endswith("/monitoring/instances")][-1]
        assert monitoring["query"]["integrationInstance"] == "prodinst"
        assert monitoring["query"]["q"] == "{timewindow:'RETENTIONPERIOD', code:'ORDER_SYNC', status:'FAILED'}"

        err, stream = await call(client, "get_instance_activity_stream", environment="prod", instance_id="OLD1")
        assert not err and stream["activityStream"]["items"][0]["message"] == "legacy stream"

        err, errors = await call(client, "list_errors", environment="prod", timewindow="1d", recoverable=True)
        assert not err and errors["filter"] == {"timewindow": "1d", "recoverable": "true"} and errors["totalResults"] == 1

        err, sched = await call(client, "list_schedules", environment="prod")
        assert not err and [s["code"] for s in sched["items"]] == ["INVOICE_LOAD"] and sched["filteredByStyle"]

        err, controls = await call(client, "summarize_flow_controls", identifier="ORDER_SYNC", environment="prod")
        assert not err and controls["controls"]["counts"]["Switch"] == 1 and controls["controls"]["counts"]["Throw fault"] == 1

        err, summary = await call(client, "summarize_integration", identifier="ORDER_SYNC|01.00.0000", environment="prod", step_names=["QueryOrders"])
        assert not err and summary["version"] == "01.00.0000"
        assert summary["steps"][0]["io"]["sql"] == ["SELECT * FROM orders WHERE id = :id"]

        err, bad = await call(client, "list_instances", environment="prod", start="last tuesday")
        assert err and "Unrecognised date/time" in bad


# --- failures are explained, never silent -----------------------------------------------------


async def test_failures_are_explained_not_returned_as_empty(server):
    async with connect(server, mode="auto") as client:
        err, text = await call(client, "search_integrations", environment="norole", query="x")
        assert err and "ServiceUser" in text

        err, text = await call(client, "get_integration", environment="norole", identifier="ORDER_SYNC")
        assert err and "ServiceUser" in text and "not found" not in text.lower()

        err, text = await call(client, "list_integrations", environment="badsecret")
        assert err and "client_id, client_secret and token_url" in text and "wrong" not in text

        err, diag = await call(client, "check_oic_connection", environment="norole")
        assert not err and diag["token"] == "ok" and diag["api"] == "failed" and "ServiceUser" in diag["diagnosis"]

        err, text = await call(client, "fetch_raw_path", environment="prod", path="//evil.example/steal")
        assert err and ("different host" in text or "absolute paths" in text)
        err, raw = await call(client, "fetch_raw_path", environment="prod", path="/ic/api/integration/v1/integrations?limit=1")
        assert not err and len(raw["json"]["items"]) == 1

        err, text = await call(client, "get_instance", environment="prod", instance_id="x", unexpected="arg")
        assert err  # schema validation by the SDK (upstream never validated)


# --- uploaded configs -------------------------------------------------------------------------------


async def test_config_upload_by_ref_header_and_delete(server, mock_oic):
    ini = env_block("qa", mock_oic.url, "qa-client", "qa-secret-XYZ")
    with httpx.Client(base_url=server.url, headers={"Authorization": f"Bearer {TOKEN}"}) as http:
        bad = http.post("/config", content="[qa]\nurl = https://x.example.com\n")
        assert bad.status_code == 400 and "missing" in bad.json()["error"]
        assert http.post("/config", content="x" * 70000).status_code == 413
        created = http.post("/config", content=ini, headers={"Content-Type": "text/plain"})
        assert created.status_code == 201
        payload = created.json()
        config_id = payload["config_id"]
        assert payload["environments"][0]["environment"] == f"{config_id}/qa" and "qa-secret" not in created.text

    async with connect(server, mode="auto") as client:
        err, found = await call(client, "search_integrations", environment=f"{config_id}/qa")
        assert not err and [i["code"] for i in found["items"]] == ["QA_FLOW"]

    async with connect(server, mode="auto", headers={"X-OIC-Config-Id": config_id}) as client:
        err, listing = await call(client, "list_oic_environments")
        assert not err and listing["configSource"] == "upload" and listing["environments"][0]["environment"] == "qa"
        assert listing["configId"] is None and config_id not in json.dumps(listing)  # model never sees the id
        err, found = await call(client, "list_integrations")
        assert not err and found["environment"] == "qa"
        err, text = await call(client, "list_integrations", environment="server/prod")
        assert err and "limited to one uploaded config" in text  # header is a hard scope

    with httpx.Client(base_url=server.url, headers={"Authorization": f"Bearer {TOKEN}"}) as http:
        assert http.delete(f"/config/{config_id}").status_code == 204

    async with connect(server, mode="auto") as client:
        err, text = await call(client, "search_integrations", environment=f"{config_id}/qa")
        assert err and "unknown or has expired" in text


# --- review findings: session spoofing and tenant isolation ---------------------------------------


def upload(server: ServerThread, mock_oic, token: str = TOKEN) -> str:
    ini = env_block("qa", mock_oic.url, "qa-client", "qa-secret-XYZ")
    with httpx.Client(base_url=server.url, headers={"Authorization": f"Bearer {token}"}) as http:
        return http.post("/config", content=ini).json()["config_id"]


async def test_forged_session_header_on_modern_requests_is_ignored(server, mock_oic):
    config_id = upload(server, mock_oic)
    seen: dict[str, str] = {}

    async def capture(resp):
        if "mcp-session-id" in resp.headers:
            seen["sid"] = resp.headers["mcp-session-id"]

    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, event_hooks={"response": [capture]}, timeout=30) as vh:
        async with Client(streamable_http_client(f"{server.url}/mcp", http_client=vh), mode="legacy") as victim:
            err, out = await call(victim, "use_oic_config", config_id=config_id)
            assert not err and out["attachedToSession"] is True
            err, mine = await call(victim, "list_integrations")
            assert not err and mine["environment"] == f"{config_id}/qa"

            # Same token, victim's session id, but sent as a 2026-07-28 request the SDK does not validate.
            async with connect(server, mode="auto", headers={"Mcp-Session-Id": seen["sid"]}) as attacker:
                assert attacker.protocol_version == "2026-07-28"
                err, text = await call(attacker, "list_integrations")
                assert err and "Several OIC environments" in text  # not the victim's uploaded config


async def test_another_token_cannot_use_an_upload(server, mock_oic):
    config_id = upload(server, mock_oic, token=TOKEN)
    async with connect(server, mode="auto", token=TOKEN_B) as other:
        err, text = await call(other, "search_integrations", environment=f"{config_id}/qa")
        assert err and "unknown or has expired" in text
    async with connect(server, mode="auto", token=TOKEN_B, headers={"X-OIC-Config-Id": config_id}) as other:
        err, text = await call(other, "list_integrations")
        assert err and "unknown or has expired" in text
    with httpx.Client(base_url=server.url, headers={"Authorization": f"Bearer {TOKEN_B}"}) as http:
        assert http.delete(f"/config/{config_id}").status_code == 404
    async with connect(server, mode="auto") as owner:
        err, found = await call(owner, "search_integrations", environment=f"{config_id}/qa")
        assert not err and found["items"][0]["code"] == "QA_FLOW"


def test_duplicate_security_headers_are_rejected(server):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    with httpx.Client(base_url=server.url) as http:
        dup = [("Authorization", f"Bearer {TOKEN}"), ("Authorization", f"Bearer {TOKEN_B}"), ("Content-Type", "application/json")]
        assert http.post("/mcp", json=body, headers=httpx.Headers(dup)).status_code == 400
        dup = [("Authorization", f"Bearer {TOKEN}"), ("Mcp-Session-Id", "a"), ("Mcp-Session-Id", "b")]
        assert http.post("/mcp", json=body, headers=httpx.Headers(dup)).status_code == 400


async def test_session_can_switch_back_to_server_config(server, mock_oic):
    config_id = upload(server, mock_oic)
    async with connect(server, mode="legacy") as client:
        err, _ = await call(client, "use_oic_config", config_id=config_id)
        assert not err
        err, text = await call(client, "search_integrations", environment="prod")
        assert err and "reachable as 'server/prod'" in text
        err, sel = await call(client, "select_oic_environment", environment="server/prod")
        assert not err and sel["remembered"] and sel["environment"] == "prod"
        err, found = await call(client, "search_integrations", query="order")
        assert not err and found["environment"] == "prod"
