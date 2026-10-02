"""Parse the OIC environments INI file.

    [prod]
    url           = https://myoic-abcdefgh-ph.integration.us-phoenix-1.ocp.oraclecloud.com
    client_id     = ...
    client_secret = ...
    token_url     = https://idcs-xxxx.identity.oraclecloud.com/oauth2/v1/token
    # optional:
    scope         = https://....urn:opc:resource:consumer::all
    instance_name = myoic-abcdefgh-ph

Values in [DEFAULT] are inherited by every section (handy for a shared token_url).
Comments must be on their own line: inline comments are NOT stripped, so a secret
containing ';' or '#' is never silently truncated.
Error messages never echo line contents, because a malformed line may hold a secret.
"""

from __future__ import annotations

import configparser
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
REQUIRED_KEYS = ("url", "client_id", "client_secret", "token_url")
KNOWN_KEYS = set(REQUIRED_KEYS) | {"scope", "instance_name", "integration_instance"}


class ConfigError(ValueError):
    """The INI content is unusable. The message is safe to show to users."""


@dataclass(frozen=True)
class InstanceConfig:
    name: str
    base_url: str
    client_id: str
    client_secret: str = field(repr=False)
    token_url: str
    scope: str | None = None
    instance_name: str | None = None
    instance_name_derived: bool = False

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    def public_view(self) -> dict[str, object]:
        """Everything except credentials - safe to return to a model or log."""
        return {
            "host": self.host,
            "integrationInstance": self.instance_name,
            "integrationInstanceDerivedFromUrl": self.instance_name_derived,
        }


def _check_url(value: str, key: str, section: str, allow_insecure: bool, host_suffixes: tuple[str, ...] = ()) -> str:
    parts = urlsplit(value.strip())
    allowed = ("https", "http") if allow_insecure else ("https",)
    if parts.scheme not in allowed or not parts.hostname:
        raise ConfigError(f"[{section}] {key} must be an https:// URL")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ConfigError(f"[{section}] {key} must not contain credentials")
    if host_suffixes and not any(parts.hostname.lower().endswith(s) for s in host_suffixes):
        raise ConfigError(f"[{section}] {key} host is not allowed on this server (allowed: {', '.join(host_suffixes)})")
    return value.strip()


def _base_url(value: str, section: str, allow_insecure: bool, host_suffixes: tuple[str, ...] = ()) -> str:
    """Reduce the OIC URL to scheme://host[:port]; any path (e.g. /ic/home) is ignored."""
    parts = urlsplit(_check_url(value, "url", section, allow_insecure, host_suffixes))
    netloc = parts.hostname.lower() if parts.hostname else ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return f"{parts.scheme}://{netloc}"


def derive_instance_name(base_url: str) -> str | None:
    """OIC Gen3 instance hosts look like <service-instance>.integration.<region>.ocp.oraclecloud.com.

    The first DNS label is the 'Service instance' shown on the OIC About page, which the
    REST API wants as ?integrationInstance=. The shared design.* host has no such label.
    """
    host = urlsplit(base_url).hostname or ""
    labels = host.split(".")
    if host.endswith(".ocp.oraclecloud.com") and ".integration." in host and labels[0] != "design":
        return labels[0]
    return None


def parse_ini(
    text: str,
    *,
    allow_insecure: bool = False,
    max_environments: int | None = None,
    allowed_host_suffixes: tuple[str, ...] = (),
) -> dict[str, InstanceConfig]:
    """Parse and validate. Uploads pass max_environments and allowed_host_suffixes;
    the admin-controlled server-side file does not."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
    except configparser.MissingSectionHeaderError as exc:
        raise ConfigError(
            f"Line {exc.lineno}: expected a section header such as [prod] before any key = value lines"
        ) from None
    except configparser.ParsingError as exc:
        lines = ", ".join(str(lineno) for lineno, _ in exc.errors)
        raise ConfigError(f"Could not parse line(s) {lines}: use 'key = value'") from None
    except configparser.DuplicateSectionError as exc:
        raise ConfigError(f"Section [{exc.section}] appears more than once") from None
    except configparser.DuplicateOptionError as exc:
        raise ConfigError(f"[{exc.section}] key '{exc.option}' appears more than once") from None
    except configparser.Error as exc:  # any other structural problem
        raise ConfigError(f"Invalid INI file ({type(exc).__name__})") from None

    if max_environments is not None and len(parser.sections()) > max_environments:
        raise ConfigError(f"Too many environments ({len(parser.sections())}); the limit is {max_environments}.")

    instances: dict[str, InstanceConfig] = {}
    for section in parser.sections():
        name = section.strip().lower()
        if not NAME_RE.match(name):
            raise ConfigError(
                f"Section name [{section}] is invalid: use letters, digits, '.', '_' or '-' (max 64 chars)"
            )
        if name in instances:
            raise ConfigError(f"Section [{section}] duplicates [{name}] (names are case-insensitive)")

        values = {k.lower(): (v or "").strip() for k, v in parser[section].items()}
        missing = [k for k in REQUIRED_KEYS if not values.get(k)]
        if missing:
            raise ConfigError(f"[{section}] is missing: {', '.join(missing)}")
        unknown = sorted(set(values) - KNOWN_KEYS)
        if unknown:
            raise ConfigError(f"[{section}] has unknown key(s): {', '.join(unknown)}")

        base = _base_url(values["url"], section, allow_insecure, allowed_host_suffixes)
        explicit = values.get("instance_name") or values.get("integration_instance") or None
        derived = None if explicit else derive_instance_name(base)
        instances[name] = InstanceConfig(
            name=name,
            base_url=base,
            client_id=values["client_id"],
            client_secret=values["client_secret"],
            token_url=_check_url(values["token_url"], "token_url", section, allow_insecure, allowed_host_suffixes),
            scope=values.get("scope") or None,
            instance_name=explicit or derived,
            instance_name_derived=derived is not None,
        )

    if not instances:
        raise ConfigError(
            "No environments found. Add at least one section, e.g. [prod] with url, client_id, "
            "client_secret and token_url."
        )
    return instances


def load_ini_file(path: str, *, allow_insecure: bool = False) -> dict[str, InstanceConfig]:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError(f"Cannot read OIC_CONFIG_FILE {path!r}: {exc.strerror}") from None
    return parse_ini(text, allow_insecure=allow_insecure)
