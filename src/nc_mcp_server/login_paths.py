"""Path limits per login (multi-user mode).

``NEXTCLOUD_MCP_LOGIN_PATHS`` maps a login to the folder prefixes it may touch, e.g.
``{"service-reader": ["Shared/Public"]}``. A login listed there is *restricted*: every request
its client sends must be a WebDAV request on a file path inside one of its prefixes (the
``Destination`` of COPY/MOVE included), or a ``SEARCH`` whose results the search tool filters.
OCS, app APIs, calendars, trash, versions and every other endpoint are refused before any
request reaches Nextcloud. Logins not listed keep the full behaviour.

The check runs on the decoded path of the final URL, so it covers every tool, present and
future, that builds a URL through the client. Paths are compared after NFC normalisation;
empty segments are dropped; ``.``, ``..``, control characters, backslashes and ``%`` are
refused outright for restricted logins (no second decoding round can turn them into a
traversal). Prefix matching is by whole path segments: ``Shared`` does not match ``Shared2``.
"""

import json
import unicodedata
from typing import cast
from urllib.parse import unquote, urlsplit

_FORBIDDEN_CHARS = frozenset("\\%")


class PathNotAllowedError(Exception):
    """A restricted login tried to reach something outside its path prefixes."""


def normalize(path: str) -> str | None:
    """Literal path -> canonical form without leading/trailing slash, or None if not acceptable."""
    if len(path) > 4096:
        return None
    text = unicodedata.normalize("NFC", path)
    if any(ch in _FORBIDDEN_CHARS or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return None
    segments = [s for s in text.split("/") if s != ""]
    if any(s in (".", "..") or s.strip() == "" for s in segments):
        return None
    return "/".join(segments)


def parse_login_paths(raw: str) -> dict[str, tuple[str, ...]]:
    """Parse the JSON value of NEXTCLOUD_MCP_LOGIN_PATHS. Raises ValueError when unusable."""
    if not raw.strip():
        return {}
    try:
        data: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS is not valid JSON ({exc.msg}).") from None
    if not isinstance(data, dict):
        # ValueError like every other config error (Config.from_env contract), not TypeError.
        raise ValueError("NEXTCLOUD_MCP_LOGIN_PATHS must be a JSON object: {login: [path prefixes]}.")  # noqa: TRY004
    out: dict[str, tuple[str, ...]] = {}
    entries = cast(dict[object, object], data)
    for login, prefixes in entries.items():
        if not isinstance(login, str) or not login.strip():
            raise ValueError("NEXTCLOUD_MCP_LOGIN_PATHS: logins must be non-empty strings.")
        if not isinstance(prefixes, list) or not prefixes:
            raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: a non-empty list of path prefixes is required.")
        clean: list[str] = []
        for p in cast(list[object], prefixes):
            n = normalize(p) if isinstance(p, str) else None
            if not n:
                raise ValueError(
                    f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: invalid prefix {p!r} (no root, '.', '..', '%' or '\\')."
                )
            clean.append(n)
        out[login] = tuple(dict.fromkeys(clean))
    return out


def inside(path: str, prefixes: tuple[str, ...]) -> bool:
    """Is the canonical path one of the prefixes or below one (whole segments)?"""
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def check_path(path: str, prefixes: tuple[str, ...]) -> str:
    """Canonical path if allowed, else PathNotAllowedError."""
    n = normalize(path)
    if n is None or not n or not inside(n, prefixes):
        raise PathNotAllowedError("Path not allowed for this login.")
    return n


def scope_search(path: str, prefixes: tuple[str, ...] | None) -> str:
    """Search scope of a restricted login: must lie inside its prefixes (ValueError otherwise)."""
    if prefixes is None:
        return path
    try:
        return check_path(path, prefixes)
    except PathNotAllowedError:
        raise ValueError(f"Search path not allowed for this login. Allowed: {', '.join(prefixes)}") from None


def filter_results(results: list[dict[str, object]], prefixes: tuple[str, ...] | None) -> list[dict[str, object]]:
    """Drop entries outside the prefixes (defence in depth for search results)."""
    if prefixes is None:
        return results
    return [r for r in results if (n := normalize(str(r.get("path", "")))) and inside(n, prefixes)]


def check_request(
    method: str, url: str, headers: dict[str, str] | None, *, base_url: str, dav_user: str, prefixes: tuple[str, ...]
) -> None:
    """Allow a request of a restricted login, or raise PathNotAllowedError."""
    base_path = urlsplit(base_url).path.rstrip("/")
    files_root = f"{base_path}/remote.php/dav/files/{dav_user}/"
    dav_root = f"{base_path}/remote.php/dav/"

    def file_path(target: str) -> str:
        parts = urlsplit(target)
        if parts.query or parts.fragment:
            raise PathNotAllowedError("Path not allowed for this login.")
        if urlsplit(base_url).netloc and parts.netloc and parts.netloc != urlsplit(base_url).netloc:
            raise PathNotAllowedError("Path not allowed for this login.")
        raw = parts.path
        if not raw.startswith(files_root):
            raise PathNotAllowedError("Only files below the allowed folders are available for this login.")
        try:
            literal = "/".join(unquote(seg, errors="strict") for seg in raw[len(files_root) :].split("/"))
        except UnicodeDecodeError:
            raise PathNotAllowedError("Path not allowed for this login.") from None
        return check_path(literal, prefixes)

    m = method.upper()
    if m == "SEARCH":
        if urlsplit(url).path not in (dav_root, dav_root.rstrip("/")):
            raise PathNotAllowedError("Path not allowed for this login.")
        return
    if m not in ("PROPFIND", "GET", "HEAD", "PUT", "MKCOL", "COPY", "MOVE", "DELETE"):
        raise PathNotAllowedError("Only files below the allowed folders are available for this login.")
    file_path(url)
    dest = next((v for k, v in (headers or {}).items() if k.lower() == "destination"), None)
    if dest is not None:
        file_path(dest)
