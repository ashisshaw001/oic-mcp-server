"""A small fake OIC + IDCS used by the end-to-end tests.

Tokens encode the client_id, so each environment in the test INI sees its own data:
  prod-client  -> ORDER_SYNC (3 versions), INVOICE_LOAD, 150 fillers (exercises paging)
  dev-client   -> DEV_ONLY_FLOW
  norole-client-> token issued, but every API call 401s (missing ServiceUser role)
  client_secret 'wrong' -> token endpoint 401 invalid_client
"""

from __future__ import annotations

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse

app = FastAPI()
STATE: dict[str, object] = {"token_calls": 0, "requests": []}

LINKS = [{"rel": "self", "href": "https://example.invalid/self"}]


def _catalogue(client: str) -> list[dict]:
    if client == "prod-client":
        items = [
            {"code": "ORDER_SYNC", "version": "01.00.0000", "name": "Order Sync", "status": "ACTIVATED", "keywords": "orders erp"},
            {"code": "ORDER_SYNC", "version": "02.00.0000", "name": "Order Sync", "status": "ACTIVATED", "keywords": "orders erp"},
            {"code": "ORDER_SYNC", "version": "03.00.0000", "name": "Order Sync", "status": "CONFIGURED", "keywords": "orders erp"},
            {"code": "INVOICE_LOAD", "version": "01.00.0000", "name": "Invoice Load", "status": "ACTIVATED",
             "style": "freeform_scheduled", "description": "Nightly AP invoice load"},
        ]
        items += [{"code": f"FILLER_{i:03d}", "version": "01.00.0000", "name": f"Filler {i}", "status": "ACTIVATED"} for i in range(150)]
    elif client == "dev-client":
        items = [{"code": "DEV_ONLY_FLOW", "version": "01.00.0000", "name": "Dev Only Flow", "status": "CONFIGURED"}]
    else:
        items = [{"code": "QA_FLOW", "version": "01.00.0000", "name": "QA Flow", "status": "ACTIVATED"}]
    for item in items:
        item["id"] = f"{item['code']}|{item['version']}"
        item["links"] = LINKS
    return items


def _client_of(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer tok-"):
        return None
    return auth[len("Bearer tok-"):].rsplit("-", 1)[0]


def _record(request: Request) -> None:
    STATE["requests"].append({"path": request.url.path, "query": dict(request.query_params)})  # type: ignore[union-attr]


def _deny(request: Request) -> JSONResponse | None:
    client = _client_of(request)
    if client is None:
        return JSONResponse({"title": "Unauthorized"}, status_code=401)
    if client == "norole-client":
        return JSONResponse({"title": "Unauthorized", "detail": "missing role"}, status_code=401)
    return None


@app.post("/oauth2/v1/token")
async def token(client_id: str = Form(...), client_secret: str = Form(...), grant_type: str = Form(...)):
    STATE["token_calls"] = int(STATE["token_calls"]) + 1  # type: ignore[arg-type]
    if client_secret == "wrong":
        return JSONResponse({"error": "invalid_client", "error_description": "Client authentication failed."}, status_code=401)
    return {"access_token": f"tok-{client_id}-{STATE['token_calls']}", "expires_in": 3600, "token_type": "Bearer"}


@app.get("/_state")
async def state():
    return STATE


@app.post("/_reset")
async def reset():
    STATE["requests"] = []
    return {"ok": True}


@app.get("/ic/api/integration/v1/integrations")
async def integrations(request: Request, offset: int = 0, limit: int = 100):
    _record(request)
    if denied := _deny(request):
        return denied
    items = _catalogue(_client_of(request) or "")
    page = items[offset: offset + limit]
    return {"items": page, "totalResults": len(items), "hasMore": offset + limit < len(items), "offset": offset, "limit": limit}


@app.get("/ic/api/integration/v1/integrations/{ident}/schedule")
async def schedule(ident: str, request: Request):
    _record(request)
    if denied := _deny(request):
        return denied
    if ident.startswith("INVOICE_LOAD|"):
        return {"name": "Nightly", "state": "STARTED", "icalExpression": "FREQ=DAILY;BYHOUR=2", "links": LINKS}
    return JSONResponse({"title": "Schedule not found"}, status_code=404)


@app.get("/ic/api/integration/v1/integrations/{ident}")
async def integration(ident: str, request: Request):
    _record(request)
    if denied := _deny(request):
        return denied
    code, _, version = ident.partition("|")
    known = {i["id"] for i in _catalogue(_client_of(request) or "")}
    if ident not in known:
        return JSONResponse({"title": "Integration not found"}, status_code=404)
    return {
        "code": code,
        "version": version,
        "name": code.title(),
        "status": "ACTIVATED",
        "endPoints": [
            {"name": "GetOrders", "role": "SOURCE", "connection": {"id": "REST_TRIGGER", "adapter": "rest"}},
            {"name": "CreateInvoice", "role": "TARGET", "connection": {"id": "ERP_CLOUD", "adapter": "erp"}},
        ],
        "trackingVariables": [{"name": "orderId", "primary": True, "xpath": "/order/id"}],
        "flow": {
            "steps": [
                {"name": "MapToERP", "type": "map"},
                {"name": "RouteByType", "type": "switch", "branches": [{"name": "RejectBadOrder", "type": "throw"}]},
                {"name": "QueryOrders", "type": "invoke", "sql": "SELECT * FROM orders WHERE id = :id"},
            ]
        },
        "links": LINKS,
    }


@app.get("/ic/api/integration/v1/monitoring/instances")
async def instances(request: Request):
    _record(request)
    if denied := _deny(request):
        return denied
    items = [
        {"id": "I-1", "integrationId": "ORDER_SYNC", "status": "COMPLETED", "links": LINKS},
        {"id": "I-2", "integrationId": "ORDER_SYNC", "status": "FAILED", "links": LINKS},
    ]
    return {"items": items, "totalResults": 2, "hasMore": False}


@app.get("/ic/api/integration/v1/monitoring/instances/{iid}/activityStreamDetails")
async def activity_details(iid: str, request: Request):
    _record(request)
    if denied := _deny(request):
        return denied
    if iid == "OLD1":
        return JSONResponse({"title": "Not found"}, status_code=404)
    return {"items": [{"message": "Started", "iid": iid}]}


@app.get("/ic/api/integration/v1/monitoring/instances/{iid}/activityStream")
async def activity_legacy(iid: str, request: Request):
    _record(request)
    if denied := _deny(request):
        return denied
    return {"items": [{"message": "legacy stream", "iid": iid}]}


@app.get("/ic/api/integration/v1/monitoring/errors")
async def errors(request: Request):
    _record(request)
    if denied := _deny(request):
        return denied
    return {"items": [{"id": "I-2", "errorMessage": "ERP timeout", "recoverable": True}], "totalResults": 1, "hasMore": False}
