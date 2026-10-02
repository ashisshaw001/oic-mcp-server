"""Turn tool payloads into compact JSON text that always parses.

Upstream cut the serialized text at 100k characters, leaving broken JSON. Here an
oversized payload is shrunk by dropping list items (and saying so); if that is not
enough, a clearly-labelled text preview is returned inside valid JSON.
"""

from __future__ import annotations

import json
from typing import Any

DROP_KEYS = frozenset({"links"})  # OIC HATEOAS links: many tokens, no value to a model


def compact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: compact(v) for k, v in obj.items() if k not in DROP_KEYS}
    if isinstance(obj, list):
        return [compact(v) for v in obj]
    return obj


def dumps(obj: Any) -> str:
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
    # A lone UTF-16 surrogate (e.g. from a truncated Java string in OIC data) cannot be
    # encoded as UTF-8 and would break the whole response; replace it with '?'.
    return text.encode("utf-8", "replace").decode("utf-8")


def _largest_list_key(payload: dict[str, Any]) -> str | None:
    best, best_len = None, 0
    for key, value in payload.items():
        if isinstance(value, list) and len(value) > best_len:
            best, best_len = key, len(value)
    return best


def to_text(payload: Any, max_chars: int) -> str:
    text = dumps(payload)
    if len(text) <= max_chars:
        return text

    if isinstance(payload, dict):
        key = _largest_list_key(payload)
        if key:
            items = payload[key]
            lo, hi = 0, len(items)
            while lo < hi:  # largest prefix that fits
                mid = (lo + hi + 1) // 2
                trial = {**payload, key: items[:mid], "truncated": _note(key, mid, len(items))}
                if len(dumps(trial)) <= max_chars:
                    lo = mid
                else:
                    hi = mid - 1
            if lo > 0:
                return dumps({**payload, key: items[:lo], "truncated": _note(key, lo, len(items))})

    note = {
        "truncated": {
            "originalChars": len(text),
            "hint": "Result too large. Narrow the request (filters, limit, a specific version or step).",
        }
    }
    # The preview is re-escaped when embedded as a JSON string (quotes and backslashes double),
    # so find the longest prefix whose escaped form still fits.
    lo, hi = 0, min(len(text), max_chars)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(dumps({**note, "preview": text[:mid]})) <= max_chars:
            lo = mid
        else:
            hi = mid - 1
    return dumps({**note, "preview": text[:lo]})


def _note(key: str, shown: int, total: int) -> dict[str, Any]:
    return {
        "field": key,
        "shown": shown,
        "available": total,
        "hint": "Output trimmed to fit. Use limit/offset or narrower filters to see the rest.",
    }
