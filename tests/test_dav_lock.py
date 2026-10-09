"""HTTP 423 on a WebDAV write: say who holds the lock (Text editor, user, token), never retry."""

from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

import niquests
import pytest

from nc_mcp_server.client import NextcloudClient, NextcloudError
from nc_mcp_server.collectives_scope import CollectivesScope, ScopeView
from nc_mcp_server.config import Config
from nc_mcp_server.dav_lock import describe_lock, parse_lock_props
from nc_mcp_server.multiuser import Binding, bind

BASE = "http://nc.invalid"
PAGE = "Kollektive/Vereinswiki/Newsletter Entwurf.md"
T_LOCK = int(datetime(2026, 10, 9, 14, 24, tzinfo=ZoneInfo("Europe/Berlin")).timestamp())


def lock_xml(**props: Any) -> str:
    inner = "".join(f"<nc:{k}>{escape(str(v))}</nc:{k}>" for k, v in props.items())
    return (
        '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:nc="http://nextcloud.org/ns">'
        f"<d:response><d:href>/x</d:href><d:propstat><d:prop>{inner}</d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    )


TEXT_LOCK = {
    "lock": 1,
    "lock-owner-type": 1,
    "lock-owner-displayname": "Text",
    "lock-owner-editor": "text",
    "lock-time": T_LOCK,
    "lock-timeout": 0,
}


def resp(status: int, text: str = "") -> niquests.Response:
    r = niquests.Response()
    r.status_code = status
    r._content = text.encode()
    return r


def client_with(answers: list[niquests.Response], calls: list[str], tz: str = "Europe/Berlin") -> NextcloudClient:
    c = NextcloudClient(Config(nextcloud_url=BASE, user="max", password="pw", is_app_password=True, timezone=tz))

    async def request(method: str, url: str, **kwargs: Any) -> niquests.Response:
        calls.append(method)
        return answers.pop(0)

    session = AsyncMock()
    session.request = AsyncMock(side_effect=request)
    c._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
    return c


class TestDescribe:
    def test_text_editor_app_lock(self) -> None:
        props = parse_lock_props(lock_xml(**TEXT_LOCK))
        m = describe_lock(PAGE, props, now=T_LOCK + 60, timezone="Europe/Berlin")
        assert "locked by the Text editor (app lock)" in m
        assert "since 2026-10-09 14:24 Europe/Berlin" in m
        assert "without expiry" in m
        assert "every open editor session" in m
        assert "background jobs (cron)" in m
        assert "probably orphaned" not in m
        assert m.endswith("Not retried.")

    def test_old_text_lock_is_probably_orphaned(self) -> None:
        m = describe_lock(PAGE, parse_lock_props(lock_xml(**TEXT_LOCK)), now=T_LOCK + 45 * 60, timezone="Europe/Berlin")
        assert "held for 45 minutes: probably orphaned, check the background jobs" in m

    def test_user_lock_names_the_user_never_an_email(self) -> None:
        user = {**TEXT_LOCK, "lock-owner-type": 0, "lock-owner-displayname": "Kim Beispiel", "lock-timeout": 1800}
        m = describe_lock(PAGE, parse_lock_props(lock_xml(**user)), now=T_LOCK, timezone="Europe/Berlin")
        assert "locked by Kim Beispiel (user lock)" in m
        assert "until 14:54 Europe/Berlin" in m
        mail = {**user, "lock-owner-displayname": "kim@example.org"}
        m = describe_lock(PAGE, parse_lock_props(lock_xml(**mail)), now=T_LOCK, timezone="Europe/Berlin")
        assert "@" not in m.replace(PAGE, "")
        assert "another user (user lock)" in m

    def test_token_lock_and_unknown(self) -> None:
        tok = {**TEXT_LOCK, "lock-owner-type": 2}
        assert "a WebDAV client (token lock)" in describe_lock(PAGE, parse_lock_props(lock_xml(**tok)), now=T_LOCK)
        assert "who holds the lock could not be read" in describe_lock(PAGE, {}, now=T_LOCK)
        assert "UTC" in describe_lock(PAGE, parse_lock_props(lock_xml(**TEXT_LOCK)), now=T_LOCK)

    def test_app_name_is_only_an_id(self) -> None:
        odd = {**TEXT_LOCK, "lock-owner-editor": "<script>"}
        assert "locked by an app (app lock)" in describe_lock(PAGE, parse_lock_props(lock_xml(**odd)), now=T_LOCK)


class TestClient:
    async def test_put_423_reads_the_lock_once_and_does_not_retry(self) -> None:
        calls: list[str] = []
        c = client_with([resp(423), resp(207, lock_xml(**TEXT_LOCK))], calls)
        with pytest.raises(NextcloudError) as err:
            await c.dav_put(PAGE, b"neu")
        assert err.value.status_code == 423
        assert "Text editor (app lock)" in str(err.value)
        assert calls == ["PUT", "PROPFIND"], "one PUT, one lock read, no retry"

    async def test_unreadable_lock_still_explains(self) -> None:
        c = client_with([resp(423), resp(403)], [])
        with pytest.raises(NextcloudError, match="could not be read"):
            await c.dav_put(PAGE, b"neu")

    async def test_delete_and_move_423_explained(self) -> None:
        c = client_with([resp(423), resp(207, lock_xml(**TEXT_LOCK)), resp(423), resp(207, lock_xml(**TEXT_LOCK))], [])
        with pytest.raises(NextcloudError, match="Text editor"):
            await c.dav_delete(PAGE)
        with pytest.raises(NextcloudError, match="Text editor"):
            await c.dav_move(PAGE, "Kollektive/Vereinswiki/x.md")

    async def test_other_errors_unchanged(self) -> None:
        calls: list[str] = []
        c = client_with([resp(409)], calls)
        with pytest.raises(NextcloudError, match="Conflict"):
            await c.dav_put(PAGE, b"x")
        assert calls == ["PUT"]

    async def test_lock_read_allowed_in_a_collectives_scope(self) -> None:
        # Person with group header (K4): PUT allowed below the collective, PROPFIND (read) too.
        calls: list[str] = []
        c = client_with([resp(423), resp(207, lock_xml(**TEXT_LOCK))], calls)
        scope = c._group_scopes.setdefault("Mitglieder", CollectivesScope(c, "Mitglieder"))
        scope._view = ScopeView(ids=frozenset({1}), prefixes=("Kollektive/Vereinswiki",))
        scope._expires = float("inf")
        with (
            bind(Binding(client=c, config=c._config, collectives_group="Mitglieder")),
            pytest.raises(NextcloudError, match="Text editor"),
        ):
            await c.dav_put(PAGE, b"neu")
        assert calls == ["PUT", "PROPFIND"]


class TestFollowUp:
    def test_until_with_date_when_not_today(self) -> None:
        long_lock = {
            **TEXT_LOCK,
            "lock-owner-type": 0,
            "lock-owner-displayname": "Kim Beispiel",
            "lock-timeout": 2 * 86400,
        }
        m = describe_lock(PAGE, parse_lock_props(lock_xml(**long_lock)), now=T_LOCK, timezone="Europe/Berlin")
        assert "until 2026-10-11 14:24 Europe/Berlin" in m
        short = {**long_lock, "lock-timeout": 1800}
        assert "until 14:54 Europe/Berlin" in describe_lock(
            PAGE, parse_lock_props(lock_xml(**short)), now=T_LOCK, timezone="Europe/Berlin"
        )

    async def test_move_names_the_locked_destination(self) -> None:
        calls: list[str] = []
        dest = "Kollektive/Vereinswiki/Ziel.md"
        c = client_with([resp(423), resp(207, lock_xml(lock=0)), resp(207, lock_xml(**TEXT_LOCK))], calls)
        with pytest.raises(NextcloudError) as err:
            await c.dav_move(PAGE, dest)
        assert f"'{dest}' is locked by the Text editor" in str(err.value)
        assert calls == ["MOVE", "PROPFIND", "PROPFIND"]

    async def test_move_source_locked_reads_only_the_source(self) -> None:
        calls: list[str] = []
        c = client_with([resp(423), resp(207, lock_xml(**TEXT_LOCK))], calls)
        with pytest.raises(NextcloudError, match=f"'{PAGE}' is locked by the Text editor"):
            await c.dav_move(PAGE, "Kollektive/Vereinswiki/Ziel.md")
        assert calls == ["MOVE", "PROPFIND"]
