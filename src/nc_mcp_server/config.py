"""Configuration loaded from environment variables."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .login_paths import parse_login_limits
from .permissions import PermissionLevel


@dataclass(frozen=True)
class Config:
    """Server configuration from environment variables.

    Required:
        NEXTCLOUD_URL: Base URL of the Nextcloud instance (e.g. http://localhost:8080)
        NEXTCLOUD_USER: Username for authentication
        NEXTCLOUD_PASSWORD: App password for authentication

    Optional:
        NEXTCLOUD_MCP_PERMISSIONS: Permission level — 'read' (default), 'write', or 'destructive'
        NEXTCLOUD_MCP_HOST: Host to bind HTTP server (default: 0.0.0.0)
        NEXTCLOUD_MCP_PORT: Port for HTTP server (default: 8100)
        NEXTCLOUD_MCP_RETRY_MAX: Max retries on 429/503 (default: 3, 0 to disable)
        NEXTCLOUD_MCP_APP_PASSWORD: Set to 'true' when using an app password to skip session caching
        NEXTCLOUD_MCP_UPLOAD_ROOT: Absolute path to a local directory. When set, enables the
            upload_file_from_path tool, restricted to files under this directory (symlinks
            are resolved before the containment check). Unset by default — tool disabled.
        NEXTCLOUD_MCP_MULTIUSER: Set to 'true' to serve many Nextcloud accounts from one HTTP
            server. Every request then carries its own ``Authorization: Basic <login:app-password>``
            header; NEXTCLOUD_USER and NEXTCLOUD_PASSWORD must not be set. Requires --transport http.
        NEXTCLOUD_MCP_MULTIUSER_CACHE_SIZE: Clients kept for recent logins (default: 64).
        NEXTCLOUD_MCP_MULTIUSER_TTL: Seconds an unused login's client is kept (default: 900).
        NEXTCLOUD_MCP_LOGIN_PATHS: JSON object {login: [folder prefixes]} (multi-user mode only).
            A listed login may only reach WebDAV files below its prefixes; every other endpoint
            is refused before Nextcloud is asked (see login_paths.py). Unset: no limits.
            Long form {login: {"paths": [...], "collectives_group": "Members"}}: the login also
            reads, and only reads, the collectives whose team has that group as a direct member
            (see collectives_scope.py); such a login is always read-only.
        NEXTCLOUD_MCP_COLLECTIVES_SCOPE_TTL: Seconds the list of a login's collectives (long form
            above) is cached before Nextcloud is asked again (default: 60).
        NEXTCLOUD_MCP_TIMEZONE: IANA time zone (e.g. Europe/Berlin) for calendar times given without
            an offset. Events then carry a TZID and a VTIMEZONE. Unset: such times are UTC.
    """

    nextcloud_url: str = field(default="")
    user: str = field(default="")
    password: str = field(default="")
    permission_level: PermissionLevel = field(default=PermissionLevel.READ)
    host: str = field(default="0.0.0.0")
    port: int = field(default=8100)
    retry_max: int = field(default=3)
    is_app_password: bool = field(default=False)
    upload_root: str = field(default="")
    multiuser: bool = field(default=False)
    multiuser_cache_size: int = field(default=64)
    multiuser_ttl: float = field(default=900.0)
    # Login name for Basic Auth when it differs from the user ID (e.g. a login by e-mail address).
    # Empty means the user ID. Set per login in multi-user mode; the user ID builds DAV paths.
    login: str = field(default="")
    # IANA zone for calendar times without an offset; "" = UTC (see NEXTCLOUD_MCP_TIMEZONE).
    timezone: str = field(default="")
    # Multi-user mode: login -> allowed folder prefixes (NEXTCLOUD_MCP_LOGIN_PATHS).
    login_paths: dict[str, tuple[str, ...]] = field(default_factory=dict[str, tuple[str, ...]])
    # Set per login in multi-user mode: the prefixes of this client's login, None = unrestricted.
    path_prefixes: tuple[str, ...] | None = field(default=None)
    # Multi-user mode: login -> group whose collectives it may read (NEXTCLOUD_MCP_LOGIN_PATHS long form).
    login_collectives: dict[str, str] = field(default_factory=dict[str, str])
    # Set per login in multi-user mode: the group of this client's login, None = no collectives scope.
    collectives_group: str | None = field(default=None)
    collectives_scope_ttl: float = field(default=60.0)

    @property
    def auth_login(self) -> str:
        """The name sent with Basic Auth: the login name if known, else the user ID."""
        return self.login or self.user

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        url = os.environ.get("NEXTCLOUD_URL", "").rstrip("/")
        user = os.environ.get("NEXTCLOUD_USER", "")
        password = os.environ.get("NEXTCLOUD_PASSWORD", "")

        perm_str = os.environ.get("NEXTCLOUD_MCP_PERMISSIONS", "read").lower()
        try:
            perm = PermissionLevel(perm_str)
        except ValueError:
            valid = ", ".join(p.value for p in PermissionLevel)
            raise ValueError(f"Invalid NEXTCLOUD_MCP_PERMISSIONS='{perm_str}'. Valid values: {valid}") from None

        host = os.environ.get("NEXTCLOUD_MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("NEXTCLOUD_MCP_PORT", "8100"))
        retry_raw = os.environ.get("NEXTCLOUD_MCP_RETRY_MAX", "3")
        try:
            retry_max = int(retry_raw)
        except ValueError:
            raise ValueError(f"Invalid NEXTCLOUD_MCP_RETRY_MAX='{retry_raw}'. Expected integer >= 0.") from None

        is_app_password = _env_bool("NEXTCLOUD_MCP_APP_PASSWORD")
        multiuser = _env_bool("NEXTCLOUD_MCP_MULTIUSER")
        cache_size = _env_number("NEXTCLOUD_MCP_MULTIUSER_CACHE_SIZE", "64", int, minimum=1)
        ttl = _env_number("NEXTCLOUD_MCP_MULTIUSER_TTL", "900", float, minimum=1)

        login_paths, login_collectives = parse_login_limits(os.environ.get("NEXTCLOUD_MCP_LOGIN_PATHS", ""))
        scope_ttl = _env_number("NEXTCLOUD_MCP_COLLECTIVES_SCOPE_TTL", "60", float, minimum=1)

        timezone = os.environ.get("NEXTCLOUD_MCP_TIMEZONE", "").strip()
        if timezone:
            try:
                ZoneInfo(timezone)
            except (ZoneInfoNotFoundError, ValueError):
                raise ValueError(
                    f"Invalid NEXTCLOUD_MCP_TIMEZONE='{timezone}'. Expected an IANA name like Europe/Berlin."
                ) from None

        upload_root_raw = os.environ.get("NEXTCLOUD_MCP_UPLOAD_ROOT", "").strip()
        if upload_root_raw:
            root = Path(upload_root_raw).expanduser()
            if not root.exists():
                raise ValueError(f"NEXTCLOUD_MCP_UPLOAD_ROOT='{upload_root_raw}' does not exist.")
            if not root.is_dir():
                raise ValueError(f"NEXTCLOUD_MCP_UPLOAD_ROOT='{upload_root_raw}' is not a directory.")
            upload_root = str(root.resolve(strict=True))
        else:
            upload_root = ""

        return cls(
            nextcloud_url=url,
            user=user,
            password=password,
            permission_level=perm,
            host=host,
            port=port,
            retry_max=max(0, retry_max),
            is_app_password=is_app_password,
            upload_root=upload_root,
            multiuser=multiuser,
            multiuser_cache_size=int(cache_size),
            multiuser_ttl=float(ttl),
            timezone=timezone,
            login_paths=login_paths,
            login_collectives=login_collectives,
            collectives_scope_ttl=float(scope_ttl),
        )

    def validate(self) -> None:
        """Raise ValueError if required config is missing."""
        missing: list[str] = []
        if not self.nextcloud_url:
            missing.append("NEXTCLOUD_URL")
        if self.multiuser:
            # No fallback account: a request without its own login must fail, not run as someone else.
            if self.user or self.password:
                raise ValueError(
                    "NEXTCLOUD_MCP_MULTIUSER=true takes the login from each request; "
                    "unset NEXTCLOUD_USER and NEXTCLOUD_PASSWORD."
                )
            if self.upload_root:
                raise ValueError("NEXTCLOUD_MCP_UPLOAD_ROOT is not supported with NEXTCLOUD_MCP_MULTIUSER=true.")
            if missing:
                raise ValueError(
                    f"Missing required environment variables: {', '.join(missing)}. "
                    f"Set them before starting the MCP server."
                )
            return
        if self.login_paths or self.login_collectives:
            raise ValueError("NEXTCLOUD_MCP_LOGIN_PATHS needs NEXTCLOUD_MCP_MULTIUSER=true.")
        if not self.user:
            missing.append("NEXTCLOUD_USER")
        if not self.password:
            missing.append("NEXTCLOUD_PASSWORD")
        if missing:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing)}. "
                f"Set them before starting the MCP server."
            )


def _env_bool(name: str) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("", "false", "0", "no"):
        return False
    if raw in ("true", "1", "yes"):
        return True
    raise ValueError(f"Invalid {name}='{raw}'. Expected: true/false, 1/0, yes/no.")


def _env_number(name: str, default: str, kind: type[int] | type[float], minimum: float) -> float:
    raw = os.environ.get(name, default).strip()
    try:
        value = kind(raw)
    except ValueError:
        raise ValueError(f"Invalid {name}='{raw}'. Expected a number >= {minimum:g}.") from None
    if value < minimum:
        raise ValueError(f"Invalid {name}='{raw}'. Expected a number >= {minimum:g}.")
    return value
