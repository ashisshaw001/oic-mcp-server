"""OICClient against an in-process fake (httpx.MockTransport): security fixes, retries, paging, errors."""

from __future__ import annotations

import httpx
import pytest

from oic_mcp.config_parser import InstanceConfig
from oic_mcp.oic_client import OICClient, OICError, build_q, to_oic_datetime, version_key

BASE = "https://myoic-abc-ph.integration.us-phoenix-1.ocp.oraclecloud.com"
TOKEN_URL = "https://idcs-123.identity.oraclecloud.com/oauth2/v1/token"
SECRET = "s3cr3t-VALUE-never-shown"


def cfg(**overrides) -> InstanceConfig:
    values = dict(
        name="prod", base_url=BASE, client_id="cid", client_secret=SECRET, token_url=TOKEN_URL,
        scope=None, instance_name="myoic-abc-ph",
    )
    values.update(overrides)
    return InstanceConfig(**values)


class Fake:
    """Routes requests to handlers and records everything it sees."""

    def __init__(self) -> None:
        self.seen: list[httpx.Request] = []
        self.token_calls = 0
        self.api = lambda req: httpx.Response(200, json={"items": [], "hasMore": False})
        self.token = lambda req: httpx.Response(200, json={"access_token": f"T{self.token_calls}", "expires_in": 3600})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        if str(request.url).startswith(TOKEN_URL):
            self.token_calls += 1
            return self.token(request)
        return self.api(request)

    def client(self, **kw) -> OICClient:
        client = OICClient(kw.pop("config", cfg()), transport=httpx.MockTransport(self), **kw)
        return client


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(self, attempt, retry_after):
        return None

    monkeypatch.setattr(OICClient, "_backoff", instant)


# --- the upstream token-leak bug ------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ".attacker.example/steal",  # upstream: sent the bearer to <oic-host>.attacker.example
        "//attacker.example/steal",  # network-path reference switches host
        "https://attacker.example/steal",
        "ic/api/relative",
        "/ic/api/../../elsewhere",  # normalises to /elsewhere: outside /ic/api/
        "/ic/home",
        "/ic/api/x\\y",
        "/ic/api/%2e%2e/%2e%2e/ic/home",  # encoded dot-segments: checked decoded, sent encoded
        "/ic/api/%2E%2E%2Fsecret",
    ],
)
async def test_fetch_raw_rejects_anything_but_ic_api_on_the_oic_host(path):
    fake = Fake()
    client = fake.client()
    with pytest.raises(OICError):
        await client.fetch_raw(path)
    assert all(req.url.host == httpx.URL(BASE).host or str(req.url).startswith(TOKEN_URL) for req in fake.seen)
    assert not any("attacker" in str(req.url) for req in fake.seen)
    await client.aclose()


async def test_fetch_raw_allows_ic_api_and_adds_instance_and_bearer():
    fake = Fake()
    fake.api = lambda req: httpx.Response(200, json={"ok": True})
    client = fake.client()
    out = await client.fetch_raw("/ic/api/integration/v1/integrations?limit=1")
    assert out["json"] == {"ok": True}
    api_req = fake.seen[-1]
    assert api_req.url.host == httpx.URL(BASE).host
    assert api_req.headers["authorization"] == "Bearer T1"
    assert api_req.url.params["integrationInstance"] == "myoic-abc-ph"
    assert api_req.url.params["limit"] == "1"
    await client.aclose()


async def test_redirect_to_foreign_host_is_refused_without_sending_the_token():
    fake = Fake()
    fake.api = lambda req: (
        httpx.Response(307, headers={"location": "https://attacker.example/steal"})
        if req.url.host != "attacker.example"
        else httpx.Response(200, json={"stolen": req.headers.get("authorization")})
    )
    client = fake.client()
    with pytest.raises(OICError, match="unexpected host"):
        await client.get_json("/ic/api/integration/v1/integrations")
    assert not any(req.url.host == "attacker.example" for req in fake.seen)
    await client.aclose()


async def test_redirect_to_oracle_design_host_is_followed_with_token():
    design = "https://design.integration.us-phoenix-1.ocp.oraclecloud.com"
    fake = Fake()
    fake.api = lambda req: (
        httpx.Response(307, headers={"location": f"{design}{req.url.raw_path.decode()}"})
        if req.url.host != httpx.URL(design).host
        else httpx.Response(200, json={"items": [1], "hasMore": False})
    )
    client = fake.client()
    data = await client.get_json("/ic/api/integration/v1/integrations")
    assert data["items"] == [1]
    followed = fake.seen[-1]
    assert followed.url.host == httpx.URL(design).host
    assert followed.headers["authorization"].startswith("Bearer ")
    await client.aclose()


async def test_identifiers_are_encoded_as_one_path_segment():
    fake = Fake()
    fake.api = lambda req: httpx.Response(200, json={})
    client = fake.client()
    await client.connection("../../monitoring/instances")
    raw = fake.seen[-1].url.raw_path.decode()
    assert raw.startswith("/ic/api/integration/v1/connections/..%2F..%2Fmonitoring%2Finstances")
    await client.aclose()


# --- retries & error messages ----------------------------------------------------------


async def test_retries_503_then_succeeds():
    fake = Fake()
    responses = iter([httpx.Response(503), httpx.Response(503), httpx.Response(200, json={"items": []})])
    fake.api = lambda req: next(responses)
    client = fake.client(max_retries=2)
    assert await client.get_json("/ic/api/integration/v1/lookups") == {"items": []}
    assert sum(1 for r in fake.seen if "lookups" in r.url.path) == 3
    await client.aclose()


async def test_retries_exhausted_gives_clear_message():
    fake = Fake()
    fake.api = lambda req: httpx.Response(503)
    client = fake.client(max_retries=1)
    with pytest.raises(OICError, match="unavailable .* after 2 attempt"):
        await client.get_json("/ic/api/integration/v1/lookups")
    await client.aclose()


async def test_connect_errors_are_retried_then_explained():
    fake = Fake()

    def boom(req):
        raise httpx.ConnectError("nope", request=req)

    fake.api = boom
    client = fake.client(max_retries=2)
    with pytest.raises(OICError, match="Could not reach OIC"):
        await client.get_json("/ic/api/integration/v1/lookups")
    assert sum(1 for r in fake.seen if "lookups" in r.url.path) == 3
    await client.aclose()


async def test_api_401_refreshes_token_once_then_explains_serviceuser_role():
    fake = Fake()
    fake.api = lambda req: httpx.Response(401, json={"title": "Unauthorized"})
    client = fake.client()
    with pytest.raises(OICError) as info:
        await client.get_json("/ic/api/integration/v1/integrations")
    assert "ServiceUser" in str(info.value)
    assert info.value.status == 401
    assert fake.token_calls == 2  # initial + one forced refresh
    await client.aclose()


async def test_bad_client_secret_is_explained_without_leaking_it():
    fake = Fake()
    fake.token = lambda req: httpx.Response(401, json={"error": "invalid_client", "error_description": "Client authentication failed."})
    client = fake.client()
    with pytest.raises(OICError) as info:
        await client.get_json("/ic/api/integration/v1/integrations")
    message = str(info.value)
    assert "client_id, client_secret and token_url" in message
    assert SECRET not in message and SECRET not in repr(client.cfg)
    await client.aclose()


async def test_token_is_cached_between_calls():
    fake = Fake()
    fake.api = lambda req: httpx.Response(200, json={})
    client = fake.client()
    await client.get_json("/ic/api/integration/v1/lookups")
    await client.get_json("/ic/api/integration/v1/lookups")
    assert fake.token_calls == 1
    await client.aclose()


# --- catalogue paging & version resolution -------------------------------------------


def catalogue_api(items, *, ignore_offset=False, counter=None):
    def handler(req: httpx.Request) -> httpx.Response:
        if counter is not None:
            counter.append(dict(req.url.params))
        offset = 0 if ignore_offset else int(req.url.params.get("offset", 0))
        limit = int(req.url.params.get("limit", 100))
        page = items[offset: offset + limit]
        return httpx.Response(200, json={"items": page, "hasMore": offset + limit < len(items), "totalResults": len(items)})

    return handler


async def test_catalogue_pages_with_offset_not_page():
    items = [{"code": f"C{i}", "version": "01.00.0000", "status": "ACTIVATED"} for i in range(250)]
    calls: list[dict] = []
    fake = Fake()
    fake.api = catalogue_api(items, counter=calls)
    client = fake.client()
    got, complete = await client.catalogue()
    assert len(got) == 250 and complete
    assert [c["offset"] for c in calls] == ["0", "100", "200"]
    assert all("page" not in c for c in calls)
    await client.aclose()


async def test_catalogue_stops_if_server_ignores_offset():
    items = [{"code": f"C{i}", "version": "01.00.0000"} for i in range(250)]
    calls: list[dict] = []
    fake = Fake()
    fake.api = catalogue_api(items, ignore_offset=True, counter=calls)
    client = fake.client()
    got, complete = await client.catalogue()
    assert len(got) == 100 and not complete and len(calls) == 2
    await client.aclose()


async def test_resolve_prefers_highest_activated_then_highest_and_caches():
    items = [
        {"code": "ORDER_SYNC", "version": "01.00.0000", "status": "ACTIVATED"},
        {"code": "ORDER_SYNC", "version": "01.10.0000", "status": "CONFIGURED"},
        {"code": "ORDER_SYNC", "version": "01.02.0000", "status": "ACTIVATED"},
        {"code": "DRAFT", "version": "01.00.0000", "status": "CONFIGURED"},
        {"code": "DRAFT", "version": "02.00.0000", "status": "CONFIGURED"},
    ]
    calls: list[dict] = []
    fake = Fake()
    fake.api = catalogue_api(items, counter=calls)
    client = fake.client()
    assert await client.resolve("order_sync") == ("ORDER_SYNC", "01.02.0000", "latest activated version")
    assert await client.resolve("DRAFT") == ("DRAFT", "02.00.0000", "latest version (none activated)")
    assert await client.resolve("ORDER_SYNC|01.10.0000") == ("ORDER_SYNC", "01.10.0000", "as requested")
    assert len(calls) == 1  # one scan, then cached
    with pytest.raises(OICError, match="No integration with code 'MISSING'"):
        await client.resolve("MISSING")
    await client.aclose()


async def test_auth_failure_is_raised_not_turned_into_an_empty_catalogue():
    fake = Fake()
    fake.api = lambda req: httpx.Response(401)
    client = fake.client()
    with pytest.raises(OICError, match="HTTP 401"):
        await client.catalogue()
    with pytest.raises(OICError, match="HTTP 401"):
        await client.resolve("ORDER_SYNC")  # upstream said "not found" here
    await client.aclose()


# --- monitoring filters ------------------------------------------------------------------


def q_of(req: httpx.Request) -> str:
    return req.url.params.get("q", "")


async def test_instances_default_windows_and_date_normalisation():
    fake = Fake()
    fake.api = lambda req: httpx.Response(200, json={"items": [], "hasMore": False})
    client = fake.client()

    _, applied = await client.list_instances(integration=None, status=None, timewindow=None, start=None, end=None, business_id=None, limit=5, offset=0)
    assert applied == {"timewindow": "1h"} and q_of(fake.seen[-1]) == "{timewindow:'1h'}"

    _, applied = await client.list_instances(integration="ORDER_SYNC|01.00.0000", status="FAILED", timewindow=None, start=None, end=None, business_id=None, limit=5, offset=0)
    assert applied == {"timewindow": "RETENTIONPERIOD", "code": "ORDER_SYNC", "version": "01.00.0000", "status": "FAILED"}

    _, applied = await client.list_instances(integration=None, status=None, timewindow="1d", start="2026-09-29T10:00:00+05:30", end="2026-09-29", business_id="PO-77", limit=5, offset=0)
    assert applied["startdate"] == "2026-09-29 04:30:00" and applied["enddate"] == "2026-09-29 23:59:59"
    assert "timewindow" not in applied and applied["businessIDValue"] == "PO-77"
    await client.aclose()


async def test_activity_stream_falls_back_to_deprecated_endpoint():
    fake = Fake()
    fake.api = lambda req: (
        httpx.Response(404, json={"title": "Not found"})
        if req.url.path.endswith("activityStreamDetails")
        else httpx.Response(200, json={"items": ["legacy"]})
    )
    client = fake.client()
    assert await client.activity_stream("ABC", None) == {"items": ["legacy"]}
    await client.aclose()


def test_helpers():
    assert version_key("01.10.0002") > version_key("01.02.0009")
    assert to_oic_datetime("2026-09-29T14:30:00Z") == "2026-09-29 14:30:00"
    assert to_oic_datetime("2026-09-29 14:30:00") == "2026-09-29 14:30:00"
    assert to_oic_datetime("2026-09-29", end_of_day=True) == "2026-09-29 23:59:59"
    assert to_oic_datetime("0999-01-02T00:00:00Z") == "0999-01-02 00:00:00"
    for bad in ("yesterday", "0001-01-01T00:00:00+05:00"):  # the second overflowed upstream-style
        with pytest.raises(OICError):
            to_oic_datetime(bad)
    assert build_q({"code": "A", "x": None}) == "{code:'A'}"
    with pytest.raises(OICError):
        build_q({"businessIDValue": "x' or '1'='1"})


@pytest.mark.parametrize("value", ["..", ".", "", "  "])
async def test_dot_segments_are_refused_as_identifiers(value):
    fake = Fake()
    client = fake.client()
    with pytest.raises(OICError, match="Invalid identifier"):
        await client.connection(value)
    assert not any("connections" in r.url.path for r in fake.seen)
    await client.aclose()


@pytest.mark.parametrize(
    ("target", "allowed"),
    [
        ("https://design.integration.us-phoenix-1.ocp.oraclecloud.com/x", True),  # same region design host
        ("https://design.integration.us-ashburn-1.ocp.oraclecloud.com/x", False),  # other region
        ("https://othercustomer.integration.us-phoenix-1.ocp.oraclecloud.com/x", False),  # another tenant
        ("http://myoic-abc-ph.integration.us-phoenix-1.ocp.oraclecloud.com/x", False),  # downgrade
    ],
)
async def test_redirect_policy(target, allowed):
    fake = Fake()
    fake.api = lambda req: (
        httpx.Response(307, headers={"location": target})
        if req.url.host == httpx.URL(BASE).host
        else httpx.Response(200, json={"ok": True})
    )
    client = fake.client()
    if allowed:
        assert await client.get_json("/ic/api/integration/v1/integrations") == {"ok": True}
    else:
        with pytest.raises(OICError, match="refusing to forward credentials"):
            await client.get_json("/ic/api/integration/v1/integrations")
        assert not any(r.url.host == httpx.URL(target).host and r.url.host != httpx.URL(BASE).host for r in fake.seen)
    await client.aclose()


async def test_response_size_is_capped_even_without_content_length():
    fake = Fake()

    async def body():
        for _ in range(64):
            yield b"x" * 65536

    fake.api = lambda req: httpx.Response(200, headers={"content-type": "application/json"}, content=body())
    client = fake.client(max_response_bytes=1024 * 1024)
    with pytest.raises(OICError, match="larger than 1 MB"):
        await client.get_json("/ic/api/integration/v1/integrations")
    await client.aclose()


async def test_undecodable_body_is_an_oic_error():
    fake = Fake()
    fake.api = lambda req: httpx.Response(200, headers={"content-encoding": "gzip", "content-type": "application/json"}, content=b"not gzip")
    client = fake.client()
    with pytest.raises(OICError, match="unreadable response"):
        await client.get_json("/ic/api/integration/v1/integrations")
    await client.aclose()


async def test_error_details_of_unexpected_shape_do_not_crash():
    fake = Fake()
    fake.api = lambda req: httpx.Response(400, json={"title": "Bad filter", "o:errorDetails": "not a list"})
    client = fake.client()
    with pytest.raises(OICError, match="Bad filter"):
        await client.get_json("/ic/api/integration/v1/integrations")
    await client.aclose()


async def test_concurrent_401s_refresh_the_token_once():
    import asyncio

    fake = Fake()
    fake.api = lambda req: (
        httpx.Response(401) if req.headers.get("authorization") == "Bearer T1" else httpx.Response(200, json={})
    )
    client = fake.client()
    await client.token()  # T1 cached, and OIC will reject it
    await asyncio.gather(*(client.get_json("/ic/api/integration/v1/lookups") for _ in range(20)))
    assert fake.token_calls == 2  # T1, then a single refresh to T2
    await client.aclose()


async def test_retired_client_still_serves_a_call_in_progress():
    fake = Fake()
    fake.api = lambda req: httpx.Response(200, json={})
    client = fake.client()
    await client.get_json("/ic/api/integration/v1/lookups")
    client.retire()  # evicted from the cache while a tool call still holds it
    import asyncio

    await asyncio.sleep(0)  # let the background close run
    assert await client.get_json("/ic/api/integration/v1/lookups") == {}  # pool reopened, no RuntimeError
    assert client._http.is_closed  # and released again once idle
