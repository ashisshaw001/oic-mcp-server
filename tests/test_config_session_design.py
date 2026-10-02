"""INI parsing, environment resolution, design heuristics and output shaping."""

from __future__ import annotations

import json

import pytest

from oic_mcp import design
from oic_mcp.config_parser import ConfigError, derive_instance_name, parse_ini
from oic_mcp.oic_client import OICError
from oic_mcp.session_store import Registry
from oic_mcp.settings import Settings
from oic_mcp.shaping import compact, to_text

INI = """
[DEFAULT]
token_url = https://idcs-123.identity.oraclecloud.com/oauth2/v1/token

[PROD]
url = https://myoic-abc-ph.integration.us-phoenix-1.ocp.oraclecloud.com/ic/home
client_id = prod-id
client_secret = pa;ss#word%1

[dev]
url = https://design.integration.us-phoenix-1.ocp.oraclecloud.com
client_id = dev-id
client_secret = dev-secret
instance_name = devoic-xyz-ph
scope = https://aud.example.com:443urn:opc:resource:consumer::all
"""


# --- config parser ---------------------------------------------------------------------


def test_parse_ini_normalises_and_derives():
    envs = parse_ini(INI)
    assert list(envs) == ["prod", "dev"]
    prod, dev = envs["prod"], envs["dev"]
    assert prod.base_url == "https://myoic-abc-ph.integration.us-phoenix-1.ocp.oraclecloud.com"
    assert prod.token_url.endswith("/oauth2/v1/token")  # inherited from [DEFAULT]
    assert prod.client_secret == "pa;ss#word%1"  # no inline-comment stripping, no interpolation
    assert prod.instance_name == "myoic-abc-ph" and prod.instance_name_derived
    assert dev.instance_name == "devoic-xyz-ph" and not dev.instance_name_derived
    assert "pa;ss" not in repr(prod) and "dev-secret" not in json.dumps(dev.public_view())


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("url = x", "section header"),
        ("[prod]\nurl = https://a.example.com\n", "missing: client_id, client_secret, token_url"),
        ("[prod]\nurl = http://a.example.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.example.com", "https://"),
        ("[prod]\nurl = https://user:pw@a.example.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.example.com", "credentials"),
        ("[bad name!]\nurl = https://a.example.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.example.com", "invalid"),
        ("[prod]\nurl = https://a.example.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.example.com\nclientsecret=typo", "unknown key"),
        ("[prod]\nurl = https://a.example.com\n[prod]\n", "more than once"),
        ("", "No environments"),
    ],
)
def test_parse_ini_errors(text, message):
    with pytest.raises(ConfigError, match=message):
        parse_ini(text)


def test_parse_error_never_echoes_line_content():
    with pytest.raises(ConfigError) as info:
        parse_ini("[prod]\nclient_secret SUPERSECRET-no-equals-sign\n")
    assert "SUPERSECRET" not in str(info.value)


def test_derive_instance_name():
    assert derive_instance_name("https://abc-def-ph.integration.us-ashburn-1.ocp.oraclecloud.com") == "abc-def-ph"
    assert derive_instance_name("https://design.integration.us-ashburn-1.ocp.oraclecloud.com") is None
    assert derive_instance_name("https://example.com") is None


# --- environment resolution -------------------------------------------------------------


def registry(**settings) -> Registry:
    s = Settings(_env_file=None, mcp_auth_tokens="x" * 32, **settings)
    return Registry(s, parse_ini(INI))


async def test_multiple_environments_require_a_choice():
    reg = registry()
    with pytest.raises(OICError, match=r"Several OIC environments .*prod, dev"):
        await reg.resolve(None, owner="A", session_id=None, header_config_id=None)
    assert (await reg.resolve("DEV", owner="A", session_id=None, header_config_id=None)).name == "dev"
    with pytest.raises(OICError, match="Unknown environment 'uat'"):
        await reg.resolve("uat", owner="A", session_id=None, header_config_id=None)


async def test_session_selection_persists_only_with_a_session_id():
    reg = registry()
    chosen = await reg.resolve("prod", owner="A", session_id="s1", header_config_id=None)
    assert reg.select("A", "s1", chosen) is True
    assert (await reg.resolve(None, owner="A", session_id="s1", header_config_id=None)).name == "prod"
    assert reg.select("A", None, chosen) is False  # modern / stateless: nothing to remember
    with pytest.raises(OICError, match="Several"):
        await reg.resolve(None, owner="A", session_id="s2", header_config_id=None)
    with pytest.raises(OICError, match="Several"):  # same session id, different token: separate state
        await reg.resolve(None, owner="B", session_id="s1", header_config_id=None)


QA_INI = "[qa]\nurl=https://qa.example.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.example.com"


async def test_uploaded_configs_by_ref_header_and_session():
    reg = registry()
    upload = reg.add_upload(parse_ini(QA_INI), owner="A")
    ref = f"{upload.config_id}/qa"
    by_ref = await reg.resolve(ref, owner="A", session_id=None, header_config_id=None)
    assert by_ref.source == "upload" and by_ref.ref == ref
    by_header = await reg.resolve(None, owner="A", session_id=None, header_config_id=upload.config_id)
    assert by_header.name == "qa"  # single env in that config -> default
    assert reg.attach_config("A", "s9", upload.config_id)
    assert (await reg.resolve(None, owner="A", session_id="s9", header_config_id=None)).config_id == upload.config_id
    assert reg.delete_upload(upload.config_id, "A")
    with pytest.raises(OICError, match="unknown or has expired"):
        await reg.resolve(ref, owner="A", session_id=None, header_config_id=None)


async def test_uploads_belong_to_the_token_that_uploaded_them():
    reg = registry()
    upload = reg.add_upload(parse_ini(QA_INI), owner="A")
    with pytest.raises(OICError, match="unknown or has expired"):
        await reg.resolve(f"{upload.config_id}/qa", owner="B", session_id=None, header_config_id=None)
    with pytest.raises(OICError, match="unknown or has expired"):
        await reg.resolve(None, owner="B", session_id=None, header_config_id=upload.config_id)
    assert reg.delete_upload(upload.config_id, "B") is False and reg.get_upload(upload.config_id, "A")


async def test_empty_config_id_cannot_escape_header_scoping():
    reg = registry()
    upload = reg.add_upload(parse_ini(QA_INI), owner="A")
    for bad in ("/prod", "cfg_x/", " / "):
        with pytest.raises(OICError, match="Invalid environment"):
            await reg.resolve(bad, owner="A", session_id=None, header_config_id=upload.config_id)


async def test_selecting_an_uploaded_environment_sticks():
    reg = registry()
    upload = reg.add_upload(parse_ini(QA_INI), owner="A")
    chosen = await reg.resolve(f"{upload.config_id}/qa", owner="A", session_id="s1", header_config_id=None)
    assert reg.select("A", "s1", chosen)
    again = await reg.resolve(None, owner="A", session_id="s1", header_config_id=None)
    assert again.config_id == upload.config_id and again.name == "qa"


async def test_error_messages_list_names_not_config_ids():
    reg = registry()
    two = QA_INI + "\n[qa2]\nurl=https://qa.example.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.example.com"
    upload = reg.add_upload(parse_ini(two), owner="A")
    with pytest.raises(OICError) as info:
        await reg.resolve(None, owner="A", session_id=None, header_config_id=upload.config_id)
    assert "qa, qa2" in str(info.value) and upload.config_id not in str(info.value)
    with pytest.raises(OICError) as info:
        await reg.resolve(f"{upload.config_id}/nope", owner="A", session_id=None, header_config_id=None)
    assert upload.config_id not in str(info.value)


def test_upload_limits_in_parser():
    many = "".join(f"[e{i}]\nurl=https://x{i}.oraclecloud.com\nclient_id=a\nclient_secret=b\ntoken_url=https://t.oraclecloud.com\n" for i in range(51))
    with pytest.raises(ConfigError, match="Too many environments"):
        parse_ini(many, max_environments=50)
    with pytest.raises(ConfigError, match="host is not allowed"):
        parse_ini(QA_INI, allowed_host_suffixes=(".oraclecloud.com",))
    internal = "[x]\nurl=https://oic.oraclecloud.com\nclient_id=a\nclient_secret=b\ntoken_url=https://10.0.0.5/token"
    with pytest.raises(ConfigError, match="token_url host is not allowed"):
        parse_ini(internal, allowed_host_suffixes=(".oraclecloud.com",))


async def test_uploads_expire_after_idle_ttl(monkeypatch):
    reg = registry(oic_upload_ttl_secs=10)
    upload = reg.add_upload(parse_ini(QA_INI), owner="A")
    import oic_mcp.session_store as store

    real = store.time.monotonic
    monkeypatch.setattr(store.time, "monotonic", lambda: real() + 60)
    assert reg.get_upload(upload.config_id, "A") is None


def test_no_config_anywhere_explains_what_to_do():
    reg = Registry(Settings(_env_file=None, mcp_auth_tokens="x" * 32), {})
    with pytest.raises(OICError, match="POST /config"):
        reg.listing("A", None, None)


# --- design heuristics (array-walking fix) ----------------------------------------------

DESIGN = {
    "endPoints": [
        {"name": "GetOrders", "role": "SOURCE", "connection": {"id": "REST_TRIGGER", "adapter": "rest"}},
        {"name": "CreateInvoice", "role": "TARGET", "connection": {"id": "ERP", "adapter": "erp"}},
    ],
    "flow": {
        "steps": [
            {"name": "MapToERP", "type": "map"},
            {"name": "RouteByType", "type": "switch", "branches": [{"name": "RejectBadOrder", "type": "throw"}]},
            {"name": "QueryOrders", "type": "invoke", "sql": "SELECT * FROM orders WHERE id = :id"},
        ]
    },
}


def test_walk_sees_steps_stored_in_arrays():
    assert design.mappings(DESIGN)["total"] == 1
    counts = design.flow_controls(DESIGN)["counts"]
    assert counts["Switch"] == 1 and counts["Throw fault"] == 1
    outline = design.outline(DESIGN)
    assert outline[0].startswith("Trigger | GetOrders") and "Map | MapToERP" in outline and "Invoke | QueryOrders" in outline
    steps, match = design.find_steps(DESIGN, "queryorders")
    assert match == "exact" and steps[0]["type"] == "invoke"
    io = design.step_io(DESIGN, "QueryOrders")
    assert io["io"]["sql"] == ["SELECT * FROM orders WHERE id = :id"]
    endpoint_io = design.step_io(DESIGN, "CreateInvoice")  # endpoints are nodes in an array too
    assert endpoint_io["step"]["role"] == "TARGET" and endpoint_io["io"]["connection"]["connectionId"] == "ERP"
    assert design.step_io(DESIGN, "NoSuchStep")["match"] == "none"
    assert design.summary(DESIGN)["trigger"]["connectionId"] == "REST_TRIGGER"


# --- shaping ------------------------------------------------------------------------------


def test_to_text_trims_lists_and_stays_valid_json():
    payload = {"environment": "prod", "items": [{"id": i, "pad": "x" * 200} for i in range(500)]}
    text = to_text(payload, 5000)
    data = json.loads(text)
    assert len(text) <= 5000
    assert data["truncated"]["available"] == 500 and 0 < data["truncated"]["shown"] < 500


def test_to_text_falls_back_to_a_labelled_preview():
    text = to_text({"blob": "y" * 50000}, 3000)
    data = json.loads(text)
    assert len(text) <= 3000 and data["truncated"]["originalChars"] > 50000 and data["preview"]


def test_compact_drops_links_everywhere():
    assert compact({"a": 1, "links": [1], "items": [{"links": [], "b": 2}]}) == {"a": 1, "items": [{"b": 2}]}


def test_lone_surrogates_do_not_break_output():
    text = to_text({"name": "bad\ud800end"}, 1000)
    text.encode("utf-8")  # must not raise
    assert json.loads(text)["name"] == "bad?end"


@pytest.mark.parametrize("blob", ['"\\' * 20000, "<a href=\"x\">\\n</a>" * 3000])
def test_preview_fits_even_when_escaping_expands_it(blob):
    text = to_text({"blob": blob}, 3000)
    assert len(text) <= 3000 and json.loads(text)["truncated"]


def test_single_oversized_item_still_fits():
    text = to_text({"items": [{"huge": "z" * 20000}]}, 2000)
    assert len(text) <= 2000 and json.loads(text)["truncated"]


async def test_header_is_a_hard_scope_and_hides_the_config_id():
    reg = registry()
    upload = reg.add_upload(parse_ini(QA_INI), owner="A")
    got = await reg.resolve(None, owner="A", session_id=None, header_config_id=upload.config_id)
    assert got.ref == "qa" and got.via_header
    for escape in ("server/prod", "cfg_other/qa"):
        with pytest.raises(OICError, match="limited to one uploaded config"):
            await reg.resolve(escape, owner="A", session_id=None, header_config_id=upload.config_id)
    listing = reg.listing("A", None, upload.config_id)
    assert listing["configId"] is None and listing["environments"][0]["environment"] == "qa"


async def test_server_prefix_and_detaching_a_session_upload():
    reg = registry()
    upload = reg.add_upload(parse_ini(QA_INI), owner="A")
    assert reg.attach_config("A", "s1", upload.config_id)
    with pytest.raises(OICError, match="reachable as 'server/prod'"):
        await reg.resolve("prod", owner="A", session_id="s1", header_config_id=None)
    chosen = await reg.resolve("server/prod", owner="A", session_id="s1", header_config_id=None)
    assert chosen.source == "server" and reg.select("A", "s1", chosen)
    assert (await reg.resolve(None, owner="A", session_id="s1", header_config_id=None)).name == "prod"


def test_upload_quotas_are_per_token():
    reg = registry(oic_max_uploads_per_token=2, oic_max_uploaded_configs=5)
    a1 = reg.add_upload(parse_ini(QA_INI), owner="A")
    for _ in range(10):  # B churns through its own quota
        reg.add_upload(parse_ini(QA_INI), owner="B")
    assert reg.get_upload(a1.config_id, "A") is not None
    assert sum(1 for u in reg._uploads.values() if u.owner == "B") == 2
    for owner in "CDE":  # A=1, B=2, C=1, D=1 fills the cap of 5; E's upload must cost B, not A
        reg.add_upload(parse_ini(QA_INI), owner=owner)
    assert reg.get_upload(a1.config_id, "A") is not None
    assert sum(1 for u in reg._uploads.values() if u.owner == "B") == 1


def test_oic_error_messages_are_utf8_safe():
    assert str(OICError("bad\ud800title")).encode("utf-8") == b"bad?title"


def test_preview_keeps_as_much_as_fits():
    text = to_text({"blob": '"\\' * 20000}, 3000)
    data = json.loads(text)
    assert len(text) <= 3000 and len(data["preview"]) > 1000
