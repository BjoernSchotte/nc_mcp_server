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
team drops the group goes, within that time. Only a direct group membership counts; a team that
contains another team with the group does not. A failed lookup of a team leaves that collective
out; a failed listing refuses the request (fail closed).

The list endpoints answer with everything the login sees; the collectives tools filter those
answers by the same set (tools/collectives.py).
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
_LIST_ENDPOINTS = frozenset({"collectives", "collectives/search/recent"})
_ID = r"[1-9][0-9]{0,18}"
_PER_COLLECTIVE = re.compile(rf"collectives/({_ID})/(?:pages|search|tags|pages/{_ID}|pages/{_ID}/attachments)")
_CIRCLE_ID = re.compile(r"[A-Za-z0-9]{1,64}")
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


def check_collectives_request(method: str, url: str, *, base_url: str, view: ScopeView) -> None:
    """Allow a Collectives OCS request of a scoped login, or raise PathNotAllowedError."""
    parts = urlsplit(url)
    base = urlsplit(base_url)
    if parts.query or parts.fragment:
        raise PathNotAllowedError(_REFUSED)
    if parts.netloc and (parts.scheme, parts.netloc) != (base.scheme, base.netloc):
        raise PathNotAllowedError(_REFUSED)
    root = base.path.rstrip("/") + f"/ocs/v2.php/{API}/"
    if method.upper() != "GET" or not parts.path.startswith(root):
        raise PathNotAllowedError(_REFUSED)
    rest = parts.path[len(root) :]
    if rest in _LIST_ENDPOINTS:
        return
    match = _PER_COLLECTIVE.fullmatch(rest)
    if match is None or int(match.group(1)) not in view.ids:
        raise PathNotAllowedError(_REFUSED)


def has_group(members: object, group: str) -> bool:
    """Is the group a direct, active member of a team (members as the Circles API lists them)?"""
    if not isinstance(members, list):
        return False
    for raw in cast(list[object], members):
        if not isinstance(raw, dict):
            continue
        m = cast(dict[str, Any], raw)
        level = m.get("level")
        if (
            m.get("userType") == GROUP_MEMBER
            and m.get("userId") == group
            and m.get("status", "Member") == "Member"
            and isinstance(level, int)
            and level >= 1
        ):
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
