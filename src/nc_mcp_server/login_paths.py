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

Long form of an entry: ``{"login": {"paths": [...], "collectives_group": "Members"}}``. With
``collectives_group`` the login may also read, and only read, the collectives whose team has
that Nextcloud group as a direct member (see collectives_scope.py); ``paths`` may then be empty
or left out.
"""

import json
import re
import unicodedata
from typing import cast
from xml.sax.saxutils import unescape as xml_unescape
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
    """The path prefixes of NEXTCLOUD_MCP_LOGIN_PATHS (see parse_login_limits)."""
    return parse_login_limits(raw)[0]


_LONG_KEYS = frozenset({"paths", "collectives_group"})


def parse_login_limits(raw: str) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    """Parse NEXTCLOUD_MCP_LOGIN_PATHS into (login -> prefixes, login -> collectives group).

    Every listed login is restricted and appears in the first mapping, with an empty tuple when it
    only reads collectives. Raises ValueError when unusable.
    """
    if not raw.strip():
        return {}, {}
    try:
        data: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS is not valid JSON ({exc.msg}).") from None
    if not isinstance(data, dict):
        # ValueError like every other config error (Config.from_env contract), not TypeError.
        raise ValueError("NEXTCLOUD_MCP_LOGIN_PATHS must be a JSON object: {login: [path prefixes]}.")  # noqa: TRY004
    out: dict[str, tuple[str, ...]] = {}
    groups: dict[str, str] = {}
    entries = cast(dict[object, object], data)
    for login, value in entries.items():
        if not isinstance(login, str) or not login.strip():
            raise ValueError("NEXTCLOUD_MCP_LOGIN_PATHS: logins must be non-empty strings.")
        if any(k.casefold() == login.casefold() for k in out):
            raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS: {login!r} is listed twice (logins match case-insensitively).")
        prefixes, group = _entry(login, value)
        out[login] = _prefixes(login, prefixes)
        if group is not None:
            groups[login] = group
    return out, groups


def _entry(login: str, value: object) -> tuple[list[object], str | None]:
    """One entry: a list of prefixes (short form) or {"paths": [...], "collectives_group": "..."}."""
    if isinstance(value, list) and value:
        return cast(list[object], value), None
    if not isinstance(value, dict):
        raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: a non-empty list of path prefixes is required.")  # noqa: TRY004
    entry = cast(dict[object, object], value)
    unknown = [k for k in entry if k not in _LONG_KEYS]
    if unknown:
        raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: unknown keys {unknown!r}.")
    group = _group(login, entry.get("collectives_group"))
    prefixes = entry.get("paths", [])
    if not isinstance(prefixes, list):
        raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: 'paths' must be a list of path prefixes.")  # noqa: TRY004
    if not prefixes and group is None:
        raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: give 'paths', 'collectives_group' or both.")
    return cast(list[object], prefixes), group


def _prefixes(login: str, prefixes: list[object]) -> tuple[str, ...]:
    clean: list[str] = []
    for p in prefixes:
        n = normalize(p) if isinstance(p, str) else None
        if not n:
            raise ValueError(
                f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: invalid prefix {p!r} (no root, '.', '..', '%' or '\\')."
            )
        clean.append(n)
    return tuple(dict.fromkeys(clean))


def _group(login: str, value: object) -> str | None:
    """A collectives group name: a non-blank string without control characters, or None if absent."""
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 255
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)
    ):
        raise ValueError(f"NEXTCLOUD_MCP_LOGIN_PATHS[{login!r}]: 'collectives_group' must be a group name.")
    return value


def group_for(groups: dict[str, str], login: str, user_id: str) -> str | None:
    """Collectives group of an account, matched like prefixes_for. Two different groups: None (fail closed)."""
    if not groups:
        return None
    keys = {k.casefold(): v for k, v in groups.items()}
    found = {keys[n.casefold()] for n in dict.fromkeys((login, user_id)) if n and n.casefold() in keys}
    return found.pop() if len(found) == 1 else None


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
        raise ValueError("Search path not allowed for this login.") from None


def filter_results(results: list[dict[str, object]], prefixes: tuple[str, ...] | None) -> list[dict[str, object]]:
    """Drop entries outside the prefixes (defence in depth for search results)."""
    if prefixes is None:
        return results
    return [r for r in results if (n := normalize(str(r.get("path", "")))) and inside(n, prefixes)]


def prefixes_for(login_paths: dict[str, tuple[str, ...]], login: str, user_id: str) -> tuple[str, ...] | None:
    """Prefixes of an account: matched by login name or user ID, case-insensitively.

    Nextcloud accepts a login name in any letter case and often the e-mail address; the user
    ID is unique. Matching both closes the alias gap. Two entries for one account: the paths
    allowed by both win (never the union).
    """
    if not login_paths:
        return None
    keys = {k.casefold(): v for k, v in login_paths.items()}
    found = [keys[n.casefold()] for n in dict.fromkeys((login, user_id)) if n and n.casefold() in keys]
    if not found:
        return None
    merged = found[0]
    for other in found[1:]:
        merged = tuple(dict.fromkeys([p for p in merged if inside(p, other)] + [p for p in other if inside(p, merged)]))
    # Nothing in common: a prefix no real path can match (fail closed, never unrestricted).
    return merged or ("\x00",)


_HREF = re.compile(r"<(?:[A-Za-z0-9]+:)?href>(.*?)</(?:[A-Za-z0-9]+:)?href>", re.DOTALL)


def _check_search_scopes(body: object, user: str, prefixes: tuple[str, ...]) -> None:
    """Every scope href of a SEARCH body must be /files/<user>/<allowed path>."""
    if isinstance(body, bytes):
        text = body.decode("utf-8", "replace")
    elif isinstance(body, str):
        text = body
    else:
        text = ""
    hrefs: list[str] = _HREF.findall(text)
    if not hrefs or not user:
        raise PathNotAllowedError("Search scope not allowed for this login.")
    root = f"/files/{user}/"
    for h in hrefs:
        # Numeric entities (&#46;&#46;) would decode to ".." in the server's XML parser.
        if "&#" in h:
            raise PathNotAllowedError("Search scope not allowed for this login.")
        literal = xml_unescape(h.strip(), {"&quot;": '"', "&apos;": "'"})
        if not literal.startswith(root):
            raise PathNotAllowedError("Search scope not allowed for this login.")
        check_path(literal[len(root) :], prefixes)


def check_request(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    *,
    base_url: str,
    dav_user: str,
    prefixes: tuple[str, ...],
    user: str = "",
    body: object = None,
) -> None:
    """Allow a request of a restricted login, or raise PathNotAllowedError."""
    base_path = urlsplit(base_url).path.rstrip("/")
    files_root = f"{base_path}/remote.php/dav/files/{dav_user}/"
    dav_root = f"{base_path}/remote.php/dav/"

    def file_path(target: str) -> str:
        parts = urlsplit(target)
        if parts.query or parts.fragment:
            raise PathNotAllowedError("Path not allowed for this login.")
        base = urlsplit(base_url)
        if parts.netloc and (parts.scheme, parts.netloc) != (base.scheme, base.netloc):
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
        _check_search_scopes(body, user, prefixes)
        return
    if m not in ("PROPFIND", "GET", "HEAD", "PUT", "MKCOL", "COPY", "MOVE", "DELETE"):
        raise PathNotAllowedError("Only files below the allowed folders are available for this login.")
    file_path(url)
    dest = next((v for k, v in (headers or {}).items() if k.lower() == "destination"), None)
    if dest is not None:
        file_path(dest)
