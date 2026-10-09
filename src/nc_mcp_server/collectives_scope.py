"""Collectives of a group for a restricted login (multi-user mode).

``NEXTCLOUD_MCP_LOGIN_PATHS`` long form ``{"login": {"paths": [...], "collectives_group": "Members"}}``
lets a restricted login read the collectives whose team (circle) has the group ``Members`` as a
direct member, and nothing else of Collectives:

* OCS: only ``GET`` on the collectives list, the recently changed pages, and the pages, a page,
  the search, the tags and a page's attachments of a collective in that set. Share, trash and
  ``touch`` endpoints, every write, and every other app stay refused.
* WebDAV: reading (``PROPFIND``, ``GET``, ``HEAD``, ``SEARCH``) below the folders of exactly those
  collectives, on top of the login's own path prefixes. Such a login never writes, not even below
  its path prefixes, whatever rights Nextcloud gives it (and its permission cap is always READ).

The set is not configured: it is read from Nextcloud with the login itself (collectives it sees,
their team's members, the folder of each) and cached for a short time
(``NEXTCLOUD_MCP_COLLECTIVES_SCOPE_TTL``). A collective shared with the group shows up, one whose
team drops the group goes, within that time. Only a direct group membership counts (as a group
member, or as the hidden team Teams creates to mirror the group: userType 16, basedOn.source 2,
basedOn.name "group:<group>"); a real sub-team that contains the group does not. A failed
lookup of a team leaves that collective out; a failed listing refuses the request (fail closed).

The list endpoints answer with everything the login sees; the collectives tools filter those
answers by the same set (tools/collectives.py).

Per request, ``X-Nextcloud-MCP-Collectives-Group: <group>`` puts the same limit on any login (a
person's own, multi-user mode): only the collectives of that group, read **and write** (create,
change, move between them, trash, delete pages; their files: read and PUT), nothing else of
Nextcloud. A login that already has a collectives group stays read-only; a header naming another
group than its own reaches no collectives at all.
"""

import asyncio
import dataclasses
import logging
import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from .login_paths import PathNotAllowedError, normalize

if TYPE_CHECKING:
    from .client import NextcloudClient

log = logging.getLogger(__name__)

API = "apps/collectives/api/v1.0"
GROUP_MEMBER = 2  # Circles member type of a Nextcloud group
CIRCLE_MEMBER = 16  # Circles member type of a team (also the hidden team that mirrors a group)
GROUP_SOURCE = 2  # basedOn.source of the hidden team that mirrors a Nextcloud group
_LIST_ENDPOINTS = frozenset({"collectives", "collectives/search/recent"})
_ID = r"[1-9][0-9]{0,18}"
_PER_COLLECTIVE = re.compile(rf"collectives/({_ID})/(?:pages|search|tags|pages/{_ID}|pages/{_ID}/attachments)")
_CIRCLE_ID = re.compile(r"[A-Za-z0-9]{1,64}")
# Writes of a writable scope (header): (method, pattern); group 1 = collective, "to" = target collective.
_WRITES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GET", re.compile(rf"collectives/({_ID})/pages/{_ID}/touch")),
    ("POST", re.compile(rf"collectives/({_ID})/pages/{_ID}")),
    ("PUT", re.compile(rf"collectives/({_ID})/pages/{_ID}")),
    ("PUT", re.compile(rf"collectives/({_ID})/pages/{_ID}/emoji")),
    ("PUT", re.compile(rf"collectives/({_ID})/pages/{_ID}/to/(?P<to>{_ID})")),
    ("DELETE", re.compile(rf"collectives/({_ID})/pages/{_ID}")),
    ("DELETE", re.compile(rf"collectives/({_ID})/pages/trash/{_ID}")),
)
GROUP_HEADER = "x-nextcloud-mcp-collectives-group"

# The group of the running request (multi-user middleware registers the provider).
_group_provider: Callable[[], str | None] | None = None


def set_request_group_provider(provider: Callable[[], str | None] | None) -> None:
    """Register the function that returns the running request's collectives group header."""
    global _group_provider
    _group_provider = provider


def request_group() -> str | None:
    """The collectives group of the running request, or None."""
    return _group_provider() if _group_provider is not None else None


def parse_group_header(value: str | None) -> str | None:
    """Parse X-Nextcloud-MCP-Collectives-Group: printable ASCII group name. ValueError when unusable."""
    if value is None:
        return None
    if not value.strip() or len(value) > 255 or any(not (0x20 <= ord(ch) < 0x7F) for ch in value):
        raise ValueError("Invalid X-Nextcloud-MCP-Collectives-Group: a group name in printable ASCII.")
    return value


_REFUSED = "This collective is not available for this login."


@dataclasses.dataclass(frozen=True)
class ScopeView:
    """The collectives a login may read now: their IDs and their folders (canonical WebDAV paths)."""

    ids: frozenset[int]
    prefixes: tuple[str, ...]


def is_collectives_ocs(url: str, base_url: str) -> bool:
    """Does the URL point into the Collectives OCS API of this server (literal path, no decoding)?"""
    root = urlsplit(base_url).path.rstrip("/") + f"/ocs/v2.php/{API}/"
    return urlsplit(url).path.startswith(root)


def check_collectives_request(method: str, url: str, *, base_url: str, view: ScopeView, writable: bool = False) -> None:
    """Allow a Collectives OCS request of a scoped login, or raise PathNotAllowedError.

    writable: also the page writes of _WRITES (header scope); every collective they touch, the
    target of a move included, must be in the view.
    """
    parts = urlsplit(url)
    base = urlsplit(base_url)
    if parts.query or parts.fragment:
        raise PathNotAllowedError(_REFUSED)
    if parts.netloc and (parts.scheme, parts.netloc) != (base.scheme, base.netloc):
        raise PathNotAllowedError(_REFUSED)
    root = base.path.rstrip("/") + f"/ocs/v2.php/{API}/"
    if not parts.path.startswith(root):
        raise PathNotAllowedError(_REFUSED)
    rest = parts.path[len(root) :]
    m = method.upper()
    if m == "GET":
        if rest in _LIST_ENDPOINTS:
            return
        match = _PER_COLLECTIVE.fullmatch(rest)
        if match is not None and int(match.group(1)) in view.ids:
            return
    if writable and _write_allowed(m, rest, view):
        return
    raise PathNotAllowedError(_REFUSED)


def _write_allowed(method: str, rest: str, view: ScopeView) -> bool:
    """A page write of _WRITES whose collectives (a move's target too) are all in the view."""
    for verb, pattern in _WRITES:
        hit = pattern.fullmatch(rest) if verb == method else None
        if hit is None:
            continue
        targets = [int(hit.group(1))] + ([int(hit.group("to"))] if "to" in pattern.groupindex else [])
        if all(t in view.ids for t in targets):
            return True
    return False


def _is_group(m: dict[str, Any], group: str) -> bool:
    """Does this team member stand for the Nextcloud group itself?

    Teams lists an added Nextcloud group either as a group member (userType 2, userId = group) or,
    as Nextcloud 34 does, as the hidden team that mirrors the group: userType 16 with
    basedOn.source 2 and basedOn.name "group:<group>". A real sub-team (basedOn.source 16) of the
    same name does not count.
    """
    if m.get("userType") == GROUP_MEMBER:
        return m.get("userId") == group
    if m.get("userType") != CIRCLE_MEMBER:
        return False
    based = m.get("basedOn")
    if not isinstance(based, dict):
        return False
    b = cast(dict[str, Any], based)
    return b.get("source") == GROUP_SOURCE and b.get("name") == f"group:{group}"


def has_group(members: object, group: str) -> bool:
    """Is the group a direct, active member of a team (members as the Circles API lists them)?"""
    if not isinstance(members, list):
        return False
    for raw in cast(list[object], members):
        if not isinstance(raw, dict):
            continue
        m = cast(dict[str, Any], raw)
        level = m.get("level")
        if _is_group(m, group) and m.get("status") == "Member" and isinstance(level, int) and level >= 1:
            return True
    return False


class CollectivesScope:
    """The collectives of a group, as one login sees them; cached for ``ttl`` seconds."""

    def __init__(
        self,
        client: "NextcloudClient",
        group: str,
        *,
        ttl: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self.group = group
        self._ttl = ttl
        self._clock = clock
        self._view: ScopeView | None = None
        self._expires = 0.0
        self._lock = asyncio.Lock()

    async def view(self) -> ScopeView:
        """The current set; asks Nextcloud when the cached one expired. Raises NextcloudError when it cannot."""
        if self._view is not None and self._clock() < self._expires:
            return self._view
        async with self._lock:
            if self._view is not None and self._clock() < self._expires:
                return self._view
            view = await self._load()
            self._view, self._expires = view, self._clock() + self._ttl
            return view

    async def _load(self) -> ScopeView:
        from .client import NextcloudError  # noqa: PLC0415 (client.py imports this module)

        client = self._client
        data = await client.ocs_get_unchecked(f"{API}/collectives")
        listing = cast(dict[str, Any], data) if isinstance(data, dict) else {}
        collectives = cast(list[object], listing.get("collectives", []))
        ids: list[int] = []
        prefixes: list[str] = []
        for raw in collectives:
            if not isinstance(raw, dict):
                continue
            c = cast(dict[str, Any], raw)
            cid, circle = c.get("id"), c.get("circleId")
            if not isinstance(cid, int) or isinstance(cid, bool) or cid < 1:
                continue
            if not isinstance(circle, str) or not _CIRCLE_ID.fullmatch(circle):
                continue
            try:
                members = await client.ocs_get_unchecked(f"apps/circles/circles/{circle}/members")
            except NextcloudError as exc:
                log.warning("Collective %d left out: its team could not be read (%s)", cid, exc)
                continue
            if not has_group(members, self.group):
                continue
            ids.append(cid)
            folder = await self._folder(cid)
            if folder:
                prefixes.append(folder)
        return ScopeView(ids=frozenset(ids), prefixes=tuple(dict.fromkeys(prefixes)))

    async def _folder(self, collective_id: int) -> str | None:
        """The collective's folder in the login's files, read from its pages (collectivePath)."""
        from .client import NextcloudError  # noqa: PLC0415 (client.py imports this module)

        try:
            data = await self._client.ocs_get_unchecked(f"{API}/collectives/{collective_id}/pages")
        except NextcloudError as exc:
            log.warning("Collective %d: its folder could not be read (%s)", collective_id, exc)
            return None
        listing = cast(dict[str, Any], data) if isinstance(data, dict) else {}
        pages = cast(list[object], listing.get("pages", []))
        for raw in pages:
            if isinstance(raw, dict):
                path = normalize(str(cast(dict[str, Any], raw).get("collectivePath") or ""))
                if path:
                    return path
        return None
