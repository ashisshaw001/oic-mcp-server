"""MCP tool definitions. Thin wrappers: resolve the environment, call OICClient, shape output.

Every OIC tool takes an optional `environment` (an INI section, e.g. 'prod'). The parameter
is deliberately not called `instance`: in OIC an "instance" is a runtime execution
(list_instances, get_instance), and a model should never have to guess which is meant.
"""

from __future__ import annotations

import base64
import functools
import logging
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from mcp import MCPError
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
from pydantic import Field

from . import design
from .oic_client import OICClient, OICError, archive_listing, as_list
from .security import principal_of
from .session_store import Registry, Resolved
from .settings import Settings
from .shaping import compact, to_text

logger = logging.getLogger(__name__)

INSTRUCTIONS = """\
Read-only monitoring for Oracle Integration Cloud (OIC). Nothing here changes OIC.
Environments: every tool takes an optional `environment`. If several are configured and the user has
not said which, call list_oic_environments, ask the user, then pass `environment` on each call.
Use exactly the environment strings list_oic_environments returns.
Always tell the user which environment the data came from (every result includes it).
Integrations are identified as CODE or CODE|VERSION; without a version the latest activated version is
used (see versionResolution in results).
list_instances / list_errors cover the last hour unless you pass timewindow (1h, 6h, 1d, 2d, 3d,
RETENTIONPERIOD) or start/end; filtering by integration or business_id searches the whole retention
period. Use business_id to find the run for a specific order, invoice or other tracked value.
Large results are trimmed and marked 'truncated'; page with limit/offset or narrow the filters."""

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
SESSION_ONLY = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

Environment = Annotated[
    str | None,
    Field(
        description="OIC environment (INI section) to query, e.g. 'prod'. Optional when only one exists or one "
        "was selected. Uploaded configs use '<config_id>/<name>'."
    ),
]
Identifier = Annotated[str, Field(description="Integration code, or CODE|VERSION.")]
Version = Annotated[str | None, Field(description="Integration version, e.g. 01.02.0000. Default: latest activated.")]
IntegrationFilter = Annotated[str | None, Field(description="Only this integration: CODE or CODE|VERSION.")]
TimeWindow = Annotated[
    Literal["1h", "6h", "1d", "2d", "3d", "RETENTIONPERIOD"] | None,
    Field(description="Look-back window. Default 1h; RETENTIONPERIOD when filtering by integration or business_id."),
]
Start = Annotated[str | None, Field(description="Range start, ISO-8601 (UTC if no offset). Overrides timewindow.")]
End = Annotated[str | None, Field(description="Range end, ISO-8601 (UTC if no offset).")]
BusinessId = Annotated[
    str | None,
    Field(description="Tracked business value to search (primary/secondary/tertiary tracking variables), e.g. an order number."),
]
Offset = Annotated[int, Field(ge=0, description="Items to skip (paging).")]
IntegrationStatus = Annotated[
    Literal["ACTIVATED", "CONFIGURED", "INPROGRESS", "FAILEDACTIVATION"] | None,
    Field(description="Integration status filter."),
]


Limit100 = Annotated[int, Field(ge=1, le=100, description="Max items to return (1-100).")]
Limit200 = Annotated[int, Field(ge=1, le=200, description="Max items to return (1-200).")]
Limit500 = Annotated[int, Field(ge=1, le=500, description="Max items to return (1-500).")]


def _integration_row(item: dict[str, Any]) -> dict[str, Any]:
    description = item.get("description")
    if isinstance(description, str) and len(description) > 200:
        description = description[:197] + "..."
    return {
        "code": item.get("code"),
        "name": item.get("name"),
        "version": item.get("version"),
        "status": item.get("status"),
        "style": item.get("style") or item.get("pattern"),
        "lastUpdated": item.get("lastUpdated"),
        "lastUpdatedBy": item.get("lastUpdatedBy"),
        "description": description,
    }


def _text_of(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(str(v) for v in value).lower()
    return str(value or "").lower()


@dataclass(frozen=True)
class Caller:
    owner: str  # principal: hash of the Bearer token
    session_id: str | None  # only when the SDK validated it
    header_config_id: str | None


def register_tools(mcp: MCPServer, registry: Registry, settings: Settings) -> None:
    max_chars = settings.max_result_chars

    def tool(description: str, annotations: ToolAnnotations = READ_ONLY):
        register = mcp.tool(description=description, annotations=annotations, structured_output=False)

        def decorate(fn):
            @functools.wraps(fn)
            async def guarded(*args: Any, **kwargs: Any) -> str:
                try:
                    return await fn(*args, **kwargs)
                except (ToolError, MCPError):
                    raise
                except Exception as exc:  # odd OIC data shapes, bugs: explain instead of a bare failure
                    logger.exception("Tool %s failed unexpectedly", fn.__name__)
                    raise OICError(
                        f"{fn.__name__} failed unexpectedly ({type(exc).__name__}); OIC may have returned data "
                        "in an unexpected shape. Details are in the server log."
                    ) from None

            return register(guarded)

        return decorate

    def caller(ctx: Context) -> Caller:
        try:
            raw = ctx.headers
            protocol = ctx.protocol_version
        except ValueError:  # called outside an HTTP request (e.g. in-memory tests)
            raw, protocol = None, None
        headers: dict[str, str] = {}
        items = raw.multi_items() if hasattr(raw, "multi_items") else (raw or {}).items()
        for key, value in items:  # first occurrence wins, matching what the SDK and middleware saw
            headers.setdefault(str(key).lower(), value)
        # The SDK validates Mcp-Session-Id only on stateful, handshake-era requests. On 2026-07-28
        # requests (and in stateless mode) the header reaches us unchecked, so it is ignored.
        trusted = not settings.mcp_stateless and protocol in HANDSHAKE_PROTOCOL_VERSIONS
        return Caller(
            owner=principal_of(headers.get("authorization")),
            session_id=headers.get("mcp-session-id") if trusted else None,
            header_config_id=headers.get("x-oic-config-id"),
        )

    async def resolve(ctx: Context, environment: str | None) -> tuple[Caller, Resolved]:
        who = caller(ctx)
        resolved = await registry.resolve(
            environment, owner=who.owner, session_id=who.session_id, header_config_id=who.header_config_id
        )
        return who, resolved

    async def env(ctx: Context, environment: str | None) -> tuple[OICClient, Resolved]:
        _, resolved = await resolve(ctx, environment)
        return registry.client_for(resolved), resolved

    def reply(resolved: Resolved, payload: dict[str, Any]) -> str:
        return to_text(compact({"environment": resolved.ref, **payload}), max_chars)

    def listed(data: Any) -> dict[str, Any]:
        data = data if isinstance(data, dict) else {"items": data}
        return {
            "items": as_list(data.get("items")),
            "totalResults": data.get("totalResults"),
            "hasMore": data.get("hasMore"),
            **({k: v for k, v in data.items() if k not in ("items", "totalResults", "hasMore", "links")}),
        }

    # ------------------------------------------------------------------ environments

    @tool("List the OIC environments available here (names and hosts, never credentials) and which one is "
          "selected. Call this when the user has not said which environment to use.")
    async def list_oic_environments(ctx: Context) -> str:
        who = caller(ctx)
        return to_text(registry.listing(who.owner, who.session_id, who.header_config_id), max_chars)

    @tool("Make an environment the default for the rest of this MCP session. Clients without sessions must "
          "pass `environment` on each call instead; the result says which applies.", SESSION_ONLY)
    async def select_oic_environment(ctx: Context, environment: Annotated[str, Field(description="Environment name, e.g. 'prod'.")]) -> str:
        who, resolved = await resolve(ctx, environment)
        remembered = registry.select(who.owner, who.session_id, resolved)
        note = (
            "Later calls in this session default to this environment."
            if remembered
            else f"This connection has no MCP session, so the choice cannot be remembered. Pass environment='{resolved.ref}' on each call."
        )
        return to_text({"environment": resolved.ref, "remembered": remembered, "note": note}, max_chars)

    @tool("Use an INI config uploaded via POST /config (identified by its config_id) for this session.", SESSION_ONLY)
    async def use_oic_config(ctx: Context, config_id: Annotated[str, Field(description="The config_id returned by POST /config.")]) -> str:
        who = caller(ctx)
        config_id = config_id.strip()
        upload = registry.get_upload(config_id, who.owner)
        if upload is None:
            raise OICError(f"Config '{config_id[:8]}…' is unknown or has expired. Upload the INI file again (POST /config).")
        attached = registry.attach_config(who.owner, who.session_id, config_id)
        refs = registry.refs(config_id, upload.environments)
        note = (
            "Later calls in this session use this config."
            if attached
            else f"This connection has no MCP session. Pass environment='<config_id>/<name>' on each call, e.g. '{refs[0]}'."
        )
        return to_text({"configId": config_id, "environments": refs, "attachedToSession": attached, "note": note}, max_chars)

    @tool("Test an environment's credentials and API access, and explain any failure (bad client secret, "
          "missing ServiceUser role, wrong URL).")
    async def check_oic_connection(ctx: Context, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        result: dict[str, Any] = {"environment": resolved.ref, **resolved.cfg.public_view()}
        try:
            await client.token(force=True)
            result["token"] = "ok"
        except OICError as exc:
            result.update(token="failed", diagnosis=str(exc))
            return to_text(result, max_chars)
        try:
            page = await client.list_integrations_page(status=None, limit=1, offset=0, order_by=None)
            result.update(api="ok", integrationVersions=page.get("totalResults"))
        except OICError as exc:
            result.update(api="failed", diagnosis=str(exc))
        return to_text(result, max_chars)

    # ------------------------------------------------------------------ integrations

    @tool("List integrations one page at a time (all versions), optionally by status. To find integrations by "
          "name or keyword use search_integrations.")
    async def list_integrations(
        ctx: Context,
        environment: Environment = None,
        status: IntegrationStatus = None,
        limit: Limit100 = 50,
        offset: Offset = 0,
        order_by: Annotated[Literal["name", "time"] | None, Field(description="Sort by name or last update time.")] = None,
    ) -> str:
        client, resolved = await env(ctx, environment)
        page = await client.list_integrations_page(status=status, limit=limit, offset=offset, order_by=order_by)
        rows = [_integration_row(i) for i in as_list(page.get("items")) if isinstance(i, dict)]
        return reply(resolved, {"items": rows, "totalResults": page.get("totalResults"), "hasMore": page.get("hasMore"), "offset": offset})

    @tool("Search every integration (all pages, all versions) by words in code, name, description or keywords. "
          "Exact code/name matches come first. An empty query lists everything (compact rows).")
    async def search_integrations(
        ctx: Context,
        query: Annotated[str, Field(description="Words to find; all must match. Empty = everything.")] = "",
        environment: Environment = None,
        status: IntegrationStatus = None,
        max_results: Limit500 = 50,
    ) -> str:
        client, resolved = await env(ctx, environment)
        items, complete = await client.catalogue()
        phrase = query.strip().lower()
        terms = phrase.split()
        exact: list[dict[str, Any]] = []
        partial: list[dict[str, Any]] = []
        for item in items:
            if status and str(item.get("status", "")).upper() != status:
                continue
            if phrase and phrase in (str(item.get("code", "")).lower(), str(item.get("name", "")).lower()):
                exact.append(item)
                continue
            haystack = " ".join(_text_of(item.get(f)) for f in ("code", "name", "description", "keywords"))
            if all(t in haystack for t in terms):
                partial.append(item)
        matches = exact + partial
        rows = [_integration_row(i) for i in matches[:max_results]]
        return reply(
            resolved,
            {
                "query": query,
                "matched": len(matches),
                "returned": len(rows),
                "catalogueSize": len(items),
                "catalogueComplete": complete,
                "items": rows,
            },
        )

    @tool("Get an integration's full design-time details (endpoints, connections, tracking variables).")
    async def get_integration(ctx: Context, identifier: Identifier, version: Version = None, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        return reply(resolved, {**meta, "integration": design.design_body(data)})

    @tool("Export an integration archive (.iar) and list its files; optionally preview small text files or "
          "return the archive as base64 (small archives only).")
    async def export_integration(
        ctx: Context,
        identifier: Identifier,
        version: Version = None,
        environment: Environment = None,
        list_only: Annotated[bool, Field(description="Only list files (default). False adds text previews of small files.")] = True,
        preview_bytes: Annotated[int, Field(ge=0, le=65536, description="Preview files up to this size.")] = 4096,
        include_archive_base64: Annotated[bool, Field(description="Also return the archive as base64 if it fits.")] = False,
    ) -> str:
        client, resolved = await env(ctx, environment)
        content, filename, meta = await client.export_archive(identifier, version)
        listing = archive_listing(content, preview_bytes=0 if list_only else preview_bytes, max_entries=300)
        out: dict[str, Any] = {**meta, "fileName": filename, "sizeBytes": len(content), **listing}
        if include_archive_base64:
            encoded = base64.b64encode(content).decode("ascii")
            if len(encoded) > max_chars - 4000:
                raise OICError(
                    f"The archive is {len(content)} bytes, too large to return inline. "
                    "Download it from the OIC console, or call again without include_archive_base64."
                )
            out["archiveBase64"] = encoded
        return reply(resolved, out)

    # ------------------------------------------------------------------ runtime monitoring

    @tool("List runtime instances (executions). Filter by integration, status, time range, or a business ID "
          "such as an order number. Default window is the last hour.")
    async def list_instances(
        ctx: Context,
        environment: Environment = None,
        integration: IntegrationFilter = None,
        status: Annotated[Literal["COMPLETED", "FAILED", "ABORTED"] | None, Field(description="Instance status.")] = None,
        timewindow: TimeWindow = None,
        start: Start = None,
        end: End = None,
        business_id: BusinessId = None,
        limit: Limit500 = 50,
        offset: Offset = 0,
    ) -> str:
        client, resolved = await env(ctx, environment)
        data, applied = await client.list_instances(
            integration=integration, status=status, timewindow=timewindow, start=start, end=end,
            business_id=business_id, limit=limit, offset=offset,
        )
        return reply(resolved, {"filter": applied, **listed(data)})

    @tool("Get one runtime instance by ID.")
    async def get_instance(ctx: Context, instance_id: Annotated[str, Field(description="Runtime instance ID.")], environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"instance": await client.instance(instance_id)})

    @tool("Get the step-by-step activity stream (actions, invokes, errors, timestamps) of one runtime instance.")
    async def get_instance_activity_stream(
        ctx: Context,
        instance_id: Annotated[str, Field(description="Runtime instance ID.")],
        environment: Environment = None,
        timezone: Annotated[str | None, Field(description="IANA timezone for timestamps, e.g. Asia/Kolkata.")] = None,
    ) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"instanceId": instance_id, "activityStream": await client.activity_stream(instance_id, timezone)})

    @tool("List errored instances. Filter by integration, time range, business ID, error text or recoverability. "
          "Default window is the last hour.")
    async def list_errors(
        ctx: Context,
        environment: Environment = None,
        integration: IntegrationFilter = None,
        timewindow: TimeWindow = None,
        start: Start = None,
        end: End = None,
        business_id: BusinessId = None,
        error_text: Annotated[str | None, Field(description="Words from the error message.")] = None,
        recoverable: Annotated[bool | None, Field(description="Only recoverable (true) or non-recoverable (false) errors.")] = None,
        limit: Limit500 = 50,
        offset: Offset = 0,
    ) -> str:
        client, resolved = await env(ctx, environment)
        data, applied = await client.list_errors(
            integration=integration, timewindow=timewindow, start=start, end=end, business_id=business_id,
            error_text=error_text, recoverable=recoverable, limit=limit, offset=offset,
        )
        return reply(resolved, {"filter": applied, **listed(data)})

    @tool("Message count summary for the environment (received, processed, succeeded, errored, aborted).")
    async def get_message_summary(ctx: Context, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"summary": await client.message_summary()})

    @tool("Historical tracking metrics grouped hourly (last 24h) or daily (last 30 days), or for a custom range.")
    async def list_metrics(
        ctx: Context,
        environment: Environment = None,
        frequency: Annotated[Literal["hourly", "daily"], Field(description="Grouping.")] = "hourly",
        timewindow: TimeWindow = None,
        start: Start = None,
        end: End = None,
    ) -> str:
        client, resolved = await env(ctx, environment)
        data, applied = await client.history(frequency=frequency, timewindow=timewindow, start=start, end=end)
        return reply(resolved, {"filter": applied, "metrics": data})

    @tool("Get the schedule of one scheduled integration.")
    async def get_schedule(ctx: Context, identifier: Identifier, version: Version = None, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.schedule(identifier, version)
        return reply(resolved, {**meta, "schedule": data})

    @tool("List schedules of scheduled integrations (checks up to `limit` integrations concurrently).")
    async def list_schedules(
        ctx: Context,
        environment: Environment = None,
        status: IntegrationStatus = "ACTIVATED",
        limit: Limit200 = 50,
    ) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, await client.schedules(status=status, limit=limit))

    # ------------------------------------------------------------------ connections & building blocks

    @tool("List connections.")
    async def list_connections(ctx: Context, environment: Environment = None, limit: Limit500 = 100, offset: Offset = 0) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, listed(await client.connections(limit=limit, offset=offset)))

    @tool("Get one connection by identifier.")
    async def get_connection(ctx: Context, identifier: Annotated[str, Field(description="Connection identifier.")], environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"connection": await client.connection(identifier)})

    @tool("List packages.")
    async def list_packages(ctx: Context, environment: Environment = None, limit: Limit500 = 100, offset: Offset = 0) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, listed(await client.packages(limit=limit, offset=offset)))

    @tool("Get one package by name.")
    async def get_package(ctx: Context, name: Annotated[str, Field(description="Package name.")], environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"package": await client.package(name)})

    @tool("List lookups.")
    async def list_lookups(ctx: Context, environment: Environment = None, limit: Limit500 = 100, offset: Offset = 0) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, listed(await client.lookups(limit=limit, offset=offset)))

    @tool("Get one lookup (with its values) by name.")
    async def get_lookup(ctx: Context, name: Annotated[str, Field(description="Lookup name.")], environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"lookup": await client.lookup(name)})

    @tool("List JavaScript libraries.")
    async def list_libraries(ctx: Context, environment: Environment = None, limit: Limit500 = 100, offset: Offset = 0) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, listed(await client.libraries(limit=limit, offset=offset)))

    @tool("Get one library by name.")
    async def get_library(ctx: Context, name: Annotated[str, Field(description="Library code/name.")], environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"library": await client.library(name)})

    @tool("List adapters.")
    async def list_adapters(ctx: Context, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, listed(await client.adapters()))

    @tool("Get one adapter by name.")
    async def get_adapter(ctx: Context, name: Annotated[str, Field(description="Adapter name.")], environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, {"adapter": await client.adapter(name)})

    @tool("List connectivity agent groups and their status.")
    async def list_agent_groups(ctx: Context, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, listed(await client.agent_groups()))

    @tool("List connectivity agents across all agent groups, with status.")
    async def list_agents(ctx: Context, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        return reply(resolved, await client.agents())

    # ------------------------------------------------------------------ design-time analysis

    @tool("Summarize an integration: trigger, targets, connections, tracking variables, status. Optionally add "
          "I/O summaries for named steps.")
    async def summarize_integration(
        ctx: Context,
        identifier: Identifier,
        version: Version = None,
        environment: Environment = None,
        step_names: Annotated[list[str] | None, Field(description="Step names to summarize too (max 20).")] = None,
    ) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        body = design.design_body(data)
        out: dict[str, Any] = {**meta, "summary": design.summary(body)}
        if step_names:
            out["steps"] = [{"stepName": n, **design.step_io(body, n)} for n in step_names[:20]]
        return reply(resolved, out)

    @tool("List an integration's endpoints (name, role, connection, adapter).")
    async def list_endpoints(ctx: Context, identifier: Identifier, version: Version = None, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        return reply(resolved, {**meta, "endPoints": design.endpoints(design.design_body(data))})

    @tool("Count and sample flow controls (Switch, For-each, Route, Throw fault, Scope) in an integration's design.")
    async def summarize_flow_controls(ctx: Context, identifier: Identifier, version: Version = None, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        return reply(resolved, {**meta, "controls": design.flow_controls(design.design_body(data))})

    @tool("List mapping steps in an integration's design (best-effort).")
    async def summarize_mappings(ctx: Context, identifier: Identifier, version: Version = None, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        return reply(resolved, {**meta, **design.mappings(design.design_body(data))})

    @tool("Compact text outline of an integration's flow (trigger, scopes, switches, maps, invokes, faults).")
    async def deep_flow_outline(ctx: Context, identifier: Identifier, version: Version = None, environment: Environment = None) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        return reply(resolved, {**meta, "outline": design.outline(design.design_body(data))})

    @tool("Return the raw design JSON of step(s) matching a name (exact first, then partial), plus matching endpoints.")
    async def get_integration_step(
        ctx: Context,
        identifier: Identifier,
        step_name: Annotated[str, Field(description="Step name to find.")],
        version: Version = None,
        environment: Environment = None,
        max_matches: Annotated[int, Field(ge=1, le=20, description="Max steps to return.")] = 5,
    ) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        body = design.design_body(data)
        steps, match = design.find_steps(body, step_name, max_matches)
        needle = step_name.strip().lower()
        eps = [e for e in design.endpoints(body) if needle in str(e.get("name") or "").lower()]
        return reply(resolved, {**meta, "stepName": step_name, "match": match if steps else "none", "steps": steps, "endpoints": eps})

    @tool("Summarize one step's inputs/outputs: suspected SQL, parameters and connection (falls back to an "
          "endpoint with that name).")
    async def summarize_step_io(
        ctx: Context,
        identifier: Identifier,
        step_name: Annotated[str, Field(description="Step name.")],
        version: Version = None,
        environment: Environment = None,
    ) -> str:
        client, resolved = await env(ctx, environment)
        data, meta = await client.integration(identifier, version)
        return reply(resolved, {**meta, "stepName": step_name, **design.step_io(design.design_body(data), step_name)})

    # ------------------------------------------------------------------ utility

    @tool("GET any OIC REST path under /ic/api/ on the environment's own host (read-only escape hatch).")
    async def fetch_raw_path(
        ctx: Context,
        path: Annotated[str, Field(description="Absolute path starting with /ic/api/, optionally with a query string.")],
        environment: Environment = None,
    ) -> str:
        client, resolved = await env(ctx, environment)
        data = await client.fetch_raw(path)
        return to_text({"environment": resolved.ref, "path": path, **data}, max_chars)
