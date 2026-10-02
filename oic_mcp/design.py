"""Best-effort analysis of an integration's design JSON.

These are heuristics: they keyword-match `type` / `name` / `role` fields, so treat the
output as a guide rather than a precise model of the flow.

Fix vs upstream: `walk` now yields dicts that are list elements. Upstream skipped them,
so any step stored in an array (the usual shape) was invisible to every analyser here.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

CONTROL_KINDS = {
    "Switch": ("switch",),
    "ForEach": ("foreach", "for each", "for-each"),
    "Route": ("route",),
    "Throw fault": ("throw",),
    "Scope": ("scope",),
}
SQL_KEYS = ("sql", "statement", "query", "select", "insert", "update", "delete")
PARAM_KEYS = ("parameters", "templateParameters", "connectivityProperties", "request", "response", "payload", "binding")


def design_body(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        content = data.get("content")
        return content if isinstance(content, dict) else data
    return {}


def walk(obj: Any) -> Iterator[tuple[Any, Any]]:
    """Yield (key, value) for every value in a JSON tree; list elements get key None."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value
            yield from walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield None, value
            yield from walk(value)


def _label(node: dict[str, Any]) -> str:
    for key in ("type", "role", "name"):
        value = node.get(key)
        if isinstance(value, str) and value:
            return value.lower()
    return ""


def endpoints(design: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    raw = design.get("endPoints")
    for ep in raw if isinstance(raw, list) else []:
        if not isinstance(ep, dict):
            continue
        conn = ep.get("connection")
        conn = conn if isinstance(conn, dict) else {"id": conn} if isinstance(conn, str) else {}
        result.append(
            {
                "name": ep.get("name"),
                "role": ep.get("role"),
                "connectionId": conn.get("id"),
                "adapter": conn.get("adapter") or conn.get("type"),
                "agentRequired": conn.get("agentRequired"),
                "privateEndpoint": conn.get("privateEndpoint"),
            }
        )
    return result


def summary(design: dict[str, Any]) -> dict[str, Any]:
    eps = endpoints(design)
    trigger = next((e for e in eps if str(e.get("role") or "").upper() in ("SOURCE", "TRIGGER")), None)
    targets = [e for e in eps if e is not trigger]
    tracking_raw = design.get("trackingVariables")
    tracking = [
        {"name": tv.get("name"), "primary": tv.get("primary"), "xpath": tv.get("xpath")}
        for tv in (tracking_raw if isinstance(tracking_raw, list) else [])
        if isinstance(tv, dict)
    ]
    return {
        "code": design.get("code"),
        "name": design.get("name"),
        "version": design.get("version"),
        "status": design.get("status"),
        "pattern": design.get("pattern") or design.get("style"),
        "description": design.get("description"),
        "lastUpdated": design.get("lastUpdated"),
        "lastUpdatedBy": design.get("lastUpdatedBy"),
        "trigger": trigger,
        "targets": targets,
        "trackingVariables": tracking,
        "counts": {"endPoints": len(eps), "trackingVariables": len(tracking)},
    }


def flow_controls(design: dict[str, Any], max_examples: int = 20) -> dict[str, Any]:
    counts = {kind: 0 for kind in CONTROL_KINDS}
    examples: list[dict[str, Any]] = []
    for _, node in walk(design):
        if not isinstance(node, dict):
            continue
        label = _label(node)
        for kind, needles in CONTROL_KINDS.items():
            if any(n in label for n in needles):
                counts[kind] += 1
                if len(examples) < max_examples:
                    examples.append({"kind": kind, "name": node.get("name"), "type": node.get("type")})
                break
    return {"counts": counts, "examples": examples}


def mappings(design: dict[str, Any], max_items: int = 50) -> dict[str, Any]:
    found = [
        {"name": node.get("name"), "type": node.get("type"), "role": node.get("role")}
        for _, node in walk(design)
        if isinstance(node, dict) and "map" in str(node.get("type") or "").lower()
    ]
    return {"mappings": found[:max_items], "total": len(found)}


def outline(design: dict[str, Any], max_lines: int = 500) -> list[str]:
    lines = [
        f"Trigger | {e.get('name') or ''} via {e.get('connectionId')} ({e.get('adapter') or 'unknown adapter'})"
        for e in endpoints(design)
        if str(e.get("role") or "").upper() in ("SOURCE", "TRIGGER")
    ]
    rules = (
        ("scope", "Scope"),
        ("switch", "Switch/If/Route"),
        ("route", "Switch/If/Route"),
        ("foreach", "For each"),
        ("for each", "For each"),
        ("throw", "Throw fault"),
        ("stitch", "Stitch"),
        ("invoke", "Invoke"),
        ("map", "Map"),
    )
    for _, node in walk(design):
        if not isinstance(node, dict):
            continue
        label = _label(node)
        for needle, text in rules:
            if needle in label or (needle == "switch" and label.startswith("if")):
                name = node.get("name")
                lines.append(f"{text} | {name}" if name else text)
                break
        if len(lines) >= max_lines:
            break
    return lines


def find_steps(design: dict[str, Any], step_name: str, max_matches: int = 5) -> tuple[list[dict[str, Any]], str]:
    needle = step_name.strip().lower()
    exact = [n for _, n in walk(design) if isinstance(n, dict) and str(n.get("name") or "").lower() == needle]
    if exact:
        return exact[:max_matches], "exact"
    fuzzy = [n for _, n in walk(design) if isinstance(n, dict) and needle in str(n.get("name") or "").lower()]
    return fuzzy[:max_matches], "partial"


def step_io(design: dict[str, Any], step_name: str) -> dict[str, Any]:
    steps, match = find_steps(design, step_name, 1)
    ep = next((e for e in endpoints(design) if str(e.get("name") or "").lower() == step_name.strip().lower()), None)
    if not steps:
        if ep:
            return {"step": {"name": ep["name"], "type": "endpoint", "role": ep["role"]}, "match": "endpoint", "io": {"connection": ep}}
        return {"step": None, "match": "none", "io": {}}
    node = steps[0]
    sql: list[str] = []
    params: dict[str, Any] = {}
    for key, value in walk(node):
        if not isinstance(key, str):
            continue
        lowered = key.lower()
        if isinstance(value, str) and any(k in lowered for k in SQL_KEYS):
            snippet = value.strip()
            if snippet and snippet not in sql:
                sql.append(snippet)
        if key in PARAM_KEYS and value is not None:
            params.setdefault(key, value)
    io: dict[str, Any] = {"sql": sql[:5], "parameters": params}
    if ep:
        io["connection"] = ep
    return {"step": {"name": node.get("name"), "type": node.get("type"), "role": node.get("role")}, "match": match, "io": io}
