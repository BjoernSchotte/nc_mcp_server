"""Collectives of a group for a restricted login (NEXTCLOUD_MCP_LOGIN_PATHS long form).

A login with ``collectives_group`` may read, and only read, the collectives whose team
(circle) has that Nextcloud group as a direct member, plus the WebDAV files below exactly
those collectives' folders. Everything else stays refused before a request is sent.
"""

import base64
import json
from typing import Any
from unittest.mock import AsyncMock

import niquests
import pytest

import nc_mcp_server.state as state_module
from nc_mcp_server.client import NextcloudClient, NextcloudError
from nc_mcp_server.collectives_scope import CollectivesScope, ScopeView, check_collectives_request
from nc_mcp_server.config import Config
from nc_mcp_server.login_paths import PathNotAllowedError, group_for, parse_login_limits, parse_login_paths
from nc_mcp_server.multiuser import Binding, ClientPool, Credentials, MultiUserAuthMiddleware, bind
from nc_mcp_server.permissions import PermissionDeniedError, PermissionLevel
from nc_mcp_server.server import create_server

BASE = "http://nc.invalid"
BOT = "itverband-claw-bot"
API = f"{BASE}/ocs/v2.php/apps/collectives/api/v1.0"
FILES = f"{BASE}/remote.php/dav/files/{BOT}"

# Fictitious collectives: 1 and 3 are shared with the group, 2 is not, 4 only via a sub-team.
COLLECTIVES = [
    {"id": 1, "name": "Vereinswiki", "circleId": "c1"},
    {"id": 2, "name": "Vorstand intern", "circleId": "c2"},
    {"id": 3, "name": "Projekte", "circleId": "c3"},
    {"id": 4, "name": "Nur Unterteam", "circleId": "c4"},
]
GROUP_MEMBER = {"userId": "Mitglieder", "userType": 2, "status": "Member", "level": 1}
MEMBERS = {
    "c1": [{"userId": "anna", "userType": 1, "status": "Member", "level": 9}, GROUP_MEMBER],
    "c2": [{"userId": "Vorstand", "userType": 2, "status": "Member", "level": 1}, {"userId": BOT, "userType": 1}],
    "c3": [GROUP_MEMBER],
    "c4": [{"userId": "Mitglieder", "userType": 16, "status": "Member", "level": 1}],
}
RECENT = [
    {"id": 11, "title": "Treffen", "collectivePath": "/Vereinswiki-1"},
    {"id": 21, "title": "Geheim", "collectivePath": "/Vorstand intern-2"},
    {"id": 99, "title": "Ohne", "collectivePath": "/"},
]
PATHS = {1: "/Kollektive/Vereinswiki", 2: "Kollektive/Vorstand intern", 3: "Kollektive/Projekte", 4: "Kollektive/X"}


def ocs(data: Any, status: int = 200) -> niquests.Response:
    r = niquests.Response()
    r.status_code = status
    r._content = json.dumps({"ocs": {"meta": {"statuscode": status, "message": ""}, "data": data}}).encode()
    return r


def fake_nextcloud(calls: list[tuple[str, str]], *, fail: str = "") -> AsyncMock:
    """A session answering the scope's own requests and recording every request sent."""

    async def request(method: str, url: str, **kwargs: Any) -> niquests.Response:
        calls.append((method, url))
        path = url.split("/ocs/v2.php/", 1)[-1]
        if fail and fail in path:
            return ocs(None, 503)
        if path == "apps/collectives/api/v1.0/collectives":
            return ocs({"collectives": COLLECTIVES})
        if path == "apps/collectives/api/v1.0/collectives/search/recent":
            return ocs({"pages": RECENT})
        if path.startswith("apps/circles/circles/") and path.endswith("/members"):
            return ocs(MEMBERS[path.split("/")[3]])
        if path.startswith("apps/collectives/api/v1.0/collectives/") and path.endswith("/pages"):
            cid = int(path.split("/")[5])
            return ocs(
                {"pages": [{"id": 10 * cid, "collectivePath": PATHS[cid], "filePath": "", "fileName": "Readme.md"}]}
            )
        r = niquests.Response()
        r.status_code = 207
        r._content = b""
        return r

    session = AsyncMock()
    session.request = AsyncMock(side_effect=request)
    return session


def scoped_client(
    calls: list[tuple[str, str]], *, prefixes: tuple[str, ...] = ("Allgemein",), fail: str = ""
) -> NextcloudClient:
    client = NextcloudClient(
        Config(
            nextcloud_url=BASE,
            user=BOT,
            password="pw",
            is_app_password=True,
            path_prefixes=prefixes,
            collectives_group="Mitglieder",
        )
    )
    session = fake_nextcloud(calls, fail=fail)
    client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
    return client


class TestParse:
    def test_short_form_unchanged(self) -> None:
        assert parse_login_limits('{"bot": ["Allgemein"]}') == ({"bot": ("Allgemein",)}, {})
        assert parse_login_paths('{"bot": ["Allgemein"]}') == {"bot": ("Allgemein",)}

    def test_long_form(self) -> None:
        raw = json.dumps(
            {
                "bot": {"paths": ["Allgemein"], "collectives_group": "Mitglieder"},
                "wiki-only": {"collectives_group": "Mitglieder"},
                "alice": ["Docs"],
            }
        )
        paths, groups = parse_login_limits(raw)
        assert paths == {"bot": ("Allgemein",), "wiki-only": (), "alice": ("Docs",)}
        assert groups == {"bot": "Mitglieder", "wiki-only": "Mitglieder"}

    @pytest.mark.parametrize(
        "raw",
        [
            '{"bot": {}}',
            '{"bot": {"paths": []}}',
            '{"bot": {"paths": ["A"], "extra": 1}}',
            '{"bot": {"collectives_group": ""}}',
            '{"bot": {"collectives_group": "  "}}',
            '{"bot": {"collectives_group": 5}}',
            '{"bot": {"collectives_group": "Mit\\nglieder"}}',
            '{"bot": {"paths": "Allgemein", "collectives_group": "M"}}',
        ],
    )
    def test_long_form_invalid(self, raw: str) -> None:
        with pytest.raises(ValueError, match="NEXTCLOUD_MCP_LOGIN_PATHS"):
            parse_login_limits(raw)

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEXTCLOUD_URL", BASE)
        monkeypatch.setenv("NEXTCLOUD_MCP_MULTIUSER", "true")
        monkeypatch.setenv(
            "NEXTCLOUD_MCP_LOGIN_PATHS", json.dumps({BOT: {"paths": ["Allgemein"], "collectives_group": "Mitglieder"}})
        )
        monkeypatch.delenv("NEXTCLOUD_USER", raising=False)
        monkeypatch.delenv("NEXTCLOUD_PASSWORD", raising=False)
        cfg = Config.from_env()
        cfg.validate()
        assert cfg.login_paths == {BOT: ("Allgemein",)}
        assert cfg.login_collectives == {BOT: "Mitglieder"}

    def test_group_for(self) -> None:
        groups = {BOT: "Mitglieder"}
        assert group_for(groups, "Itverband-Claw-Bot", BOT) == "Mitglieder"
        assert group_for(groups, "bot@example.org", BOT) == "Mitglieder", "user ID matches too"
        assert group_for(groups, "alice", "alice") is None
        assert group_for({"a": "X", "b": "Y"}, "a", "b") is None, "two different groups: none (fail closed)"
        assert group_for({"a": "X", "b": "X"}, "a", "b") == "X"


class TestCheckCollectivesRequest:
    view = ScopeView(ids=frozenset({1, 3}), prefixes=("Kollektive/Vereinswiki", "Kollektive/Projekte"))

    def check(self, method: str, url: str) -> None:
        check_collectives_request(method, url, base_url=BASE, view=self.view)

    @pytest.mark.parametrize(
        "path",
        [
            "collectives",
            "collectives/search/recent",
            "collectives/1/pages",
            "collectives/1/pages/10",
            "collectives/3/search",
            "collectives/3/tags",
            "collectives/1/pages/10/attachments",
        ],
    )
    def test_reads_of_allowed_collectives(self, path: str) -> None:
        self.check("GET", f"{API}/{path}")

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "collectives/2/pages"),
            ("GET", "collectives/2/pages/20"),
            ("GET", "collectives/4/search"),
            ("GET", "collectives/1/pages/10/touch"),
            ("GET", "collectives/1/shares"),
            ("GET", "collectives/1/pages/10/shares"),
            ("GET", "collectives/trash"),
            ("GET", "collectives/1/pages/trash"),
            ("GET", "collectives/01/pages"),
            ("GET", "collectives/1/pages/%31"),
            ("GET", "collectives/1/pages/../../2/pages"),
            ("GET", "collectives/1/pages/"),
            ("GET", "collectives/1/pages?x=1"),
            ("POST", "collectives"),
            ("POST", "collectives/1/pages/10"),
            ("PUT", "collectives/1/pages/10"),
            ("DELETE", "collectives/1/pages/10"),
            ("PATCH", "collectives/trash/1"),
        ],
    )
    def test_refused(self, method: str, path: str) -> None:
        with pytest.raises(PathNotAllowedError):
            self.check(method, f"{API}/{path}")

    def test_other_apps_and_hosts_refused(self) -> None:
        for url in [
            f"{BASE}/ocs/v2.php/apps/circles/circles/c1/members",
            f"{BASE}/ocs/v2.php/cloud/user",
            f"{BASE}/ocs/v1.php/apps/collectives/api/v1.0/collectives",
            "http://evil.invalid/ocs/v2.php/apps/collectives/api/v1.0/collectives",
        ]:
            with pytest.raises(PathNotAllowedError):
                self.check("GET", url)


class TestScope:
    async def test_only_collectives_with_the_group_as_direct_member(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        view = await client.collectives_scope.view()  # type: ignore[union-attr]
        assert view.ids == frozenset({1, 3})
        assert view.prefixes == ("Kollektive/Vereinswiki", "Kollektive/Projekte")
        # no page listing for collectives outside the scope
        assert not any("collectives/2/pages" in u or "collectives/4/pages" in u for _, u in calls)

    async def test_cached_for_the_ttl_then_reloaded(self) -> None:
        now = [1000.0]
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        scope = CollectivesScope(client, "Mitglieder", ttl=60, clock=lambda: now[0])
        await scope.view()
        first = len(calls)
        await scope.view()
        assert len(calls) == first, "cached"
        now[0] += 61
        await scope.view()
        assert len(calls) == 2 * first, "reloaded after the TTL"

    async def test_new_and_removed_collectives_follow_the_group(self) -> None:
        now = [0.0]
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        scope = CollectivesScope(client, "Mitglieder", ttl=60, clock=lambda: now[0])
        assert 2 not in (await scope.view()).ids
        MEMBERS["c2"].append(GROUP_MEMBER)
        MEMBERS["c1"].remove(GROUP_MEMBER)
        try:
            now[0] += 61
            view = await scope.view()
            assert 2 in view.ids
            assert 1 not in view.ids
        finally:
            MEMBERS["c2"].remove(GROUP_MEMBER)
            MEMBERS["c1"].append(GROUP_MEMBER)

    @pytest.mark.parametrize(
        "member",
        [
            {"userId": "mitglieder", "userType": 2, "status": "Member", "level": 1},
            {"userId": "Mitglieder", "userType": 1, "status": "Member", "level": 1},
            {"userId": "Mitglieder", "userType": 2, "status": "Invited", "level": 1},
            {"userId": "Mitglieder", "userType": 2, "status": "Member", "level": 0},
        ],
    )
    async def test_near_misses_do_not_count(self, member: dict[str, Any]) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        saved = MEMBERS["c3"]
        MEMBERS["c3"] = [member]
        try:
            view = await client.collectives_scope.view()  # type: ignore[union-attr]
            assert 3 not in view.ids
        finally:
            MEMBERS["c3"] = saved

    async def test_failed_member_lookup_leaves_that_collective_out(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls, fail="circles/c1/")
        view = await client.collectives_scope.view()  # type: ignore[union-attr]
        assert view.ids == frozenset({3})

    async def test_failed_listing_refuses(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls, fail="api/v1.0/collectives")
        with pytest.raises(NextcloudError) as err:
            await client.ocs_get("apps/collectives/api/v1.0/collectives/1/pages")
        assert err.value.status_code == 403
        assert not any(u.endswith("collectives/1/pages") and m == "GET" for m, u in calls[-1:])


class TestClientGate:
    async def test_allowed_collective_is_sent(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        await client.ocs_get("apps/collectives/api/v1.0/collectives/1/pages")
        assert calls[-1] == ("GET", f"{API}/collectives/1/pages")

    @pytest.mark.parametrize(
        "path",
        [
            "apps/collectives/api/v1.0/collectives/2/pages",
            "apps/collectives/api/v1.0/collectives/1/shares",
            "apps/circles/circles/c1/members",
            "cloud/users",
        ],
    )
    async def test_refused_never_sent(self, path: str) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        with pytest.raises(NextcloudError) as err:
            await client.ocs_get(path)
        assert err.value.status_code == 403
        assert not any(u.endswith(path) for _, u in calls)

    async def test_writes_refused_even_for_allowed_collectives(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        for call in [
            client.ocs_post_json("apps/collectives/api/v1.0/collectives/1/pages/10", {"title": "x"}),
            client.ocs_put_json("apps/collectives/api/v1.0/collectives/1/pages/10", {"title": "x"}),
            client.ocs_delete("apps/collectives/api/v1.0/collectives/1/pages/10"),
            client.dav_put("Kollektive/Vereinswiki/Readme.md", b"x"),
            client.dav_delete("Kollektive/Vereinswiki/Readme.md"),
        ]:
            with pytest.raises(NextcloudError) as err:
                await call
            assert err.value.status_code == 403
        assert not any(m in ("POST", "PUT", "DELETE") for m, _ in calls)

    async def test_dav_read_below_allowed_collectives_only(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        await client.dav_get("Kollektive/Vereinswiki/Readme.md")
        assert calls[-1] == ("GET", f"{FILES}/Kollektive/Vereinswiki/Readme.md")
        await client.dav_get("Allgemein/Satzung.md")
        for path in [
            "Kollektive/Vorstand intern/Readme.md",
            "Kollektive/Vereinswiki2/x.md",
            "Kollektive/X/a.md",
            "Vorstand/x",
        ]:
            with pytest.raises(NextcloudError):
                await client.dav_get(path)
            assert not calls[-1][1].endswith(path.replace(" ", "%20"))

    async def test_files_inside_the_path_prefixes_need_no_scope(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls, fail="api/v1.0/collectives")
        await client.dav_get("Allgemein/Satzung.md")
        assert calls == [("GET", f"{FILES}/Allgemein/Satzung.md")]

    async def test_without_a_group_collectives_stay_refused(self) -> None:
        client = NextcloudClient(
            Config(nextcloud_url=BASE, user=BOT, password="pw", is_app_password=True, path_prefixes=("Allgemein",))
        )
        session = AsyncMock()
        client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
        with pytest.raises(NextcloudError):
            await client.ocs_get("apps/collectives/api/v1.0/collectives")
        session.request.assert_not_awaited()


class TestPoolAndCap:
    async def test_pool_sets_group_and_restricts(self) -> None:
        async def lookup(base: Config, creds: Credentials) -> str:
            return creds.login

        cfg = Config(
            nextcloud_url=BASE,
            multiuser=True,
            permission_level=PermissionLevel.DESTRUCTIVE,
            login_paths={BOT: (), "files-bot": ("Allgemein",)},
            login_collectives={BOT: "Mitglieder"},
        )
        pool = ClientPool(cfg, lookup=lookup)
        client, bot = await pool.get(Credentials(BOT, "pw"))
        assert bot.collectives_group == "Mitglieder"
        assert bot.path_prefixes is not None
        assert client.collectives_scope is not None
        _, files_bot = await pool.get(Credentials("files-bot", "pw"))
        assert files_bot.collectives_group is None
        _, alice = await pool.get(Credentials("alice", "pw"))
        assert alice.collectives_group is None
        assert alice.path_prefixes is None
        await pool.close()

    async def test_login_with_a_group_is_always_read_only(self) -> None:
        seen: list[Binding] = []

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            seen.append(scope["state"]["nc_mcp_binding"])

        async def lookup(base: Config, creds: Credentials) -> str:
            return creds.login

        cfg = Config(
            nextcloud_url=BASE,
            multiuser=True,
            permission_level=PermissionLevel.DESTRUCTIVE,
            login_paths={BOT: ()},
            login_collectives={BOT: "Mitglieder"},
        )
        mw = MultiUserAuthMiddleware(app, ClientPool(cfg, lookup=lookup), PermissionLevel.DESTRUCTIVE)
        for login in (BOT, "alice"):
            token = base64.b64encode(f"{login}:pw".encode()).decode()
            headers = [(b"authorization", f"Basic {token}".encode()), (b"x-nextcloud-mcp-permissions", b"write")]
            await mw({"type": "http", "method": "POST", "headers": headers}, AsyncMock(), AsyncMock())
        assert seen[0].permission_cap == PermissionLevel.READ
        assert seen[1].permission_cap == PermissionLevel.WRITE
        await mw.pool.close()


class TestToolsFilterLists:
    @pytest.fixture(autouse=True)
    def _server(self) -> Any:
        self.mcp = create_server(Config(nextcloud_url=BASE, multiuser=True, permission_level=PermissionLevel.READ))
        yield
        state_module.set_state(None, Config())

    async def _call(self, client: NextcloudClient, tool: str, **args: Any) -> Any:
        with bind(Binding(client=client, config=client._config, permission_cap=PermissionLevel.READ)):
            result = await self.mcp._tool_manager.call_tool(tool, args)
        return json.loads(result)

    async def test_list_collectives_shows_only_the_scope(self) -> None:
        client = scoped_client([])
        out = await self._call(client, "list_collectives")
        assert [c["id"] for c in out["data"]] == [1, 3]
        assert "Vorstand intern" not in json.dumps(out)

    async def test_recent_pages_only_from_the_scope(self) -> None:
        out = await self._call(scoped_client([]), "list_recent_collective_pages")
        assert [p["id"] for p in out] == [11]

    async def test_unrestricted_login_unchanged(self) -> None:
        client = NextcloudClient(Config(nextcloud_url=BASE, user="alice", password="pw", is_app_password=True))
        session = AsyncMock()
        session.request = AsyncMock(return_value=ocs({"collectives": COLLECTIVES}))
        client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
        out = await self._call(client, "list_collectives")
        assert [c["id"] for c in out["data"]] == [1, 2, 3, 4]
        assert client.collectives_scope is None


class TestReadOnlyEvenWhenNextcloudAllowsWrites:
    """The account may write in Nextcloud (group Mitglieder can edit); nc-mcp still only reads."""

    @pytest.fixture(autouse=True)
    def _server(self) -> Any:
        self.mcp = create_server(
            Config(nextcloud_url=BASE, multiuser=True, permission_level=PermissionLevel.DESTRUCTIVE)
        )
        yield
        state_module.set_state(None, Config())

    def test_every_tool_declares_its_level(self) -> None:
        tools = self.mcp._tool_manager.list_tools()
        assert len(tools) > 100
        missing = [t.name for t in tools if not hasattr(t.fn, "_required_permission")]
        assert missing == []

    async def test_no_write_or_destructive_tool_runs_for_the_scoped_login(self) -> None:
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        # What a cap-free middleware would hand on; the pool forces READ (TestPoolAndCap), and so does this.
        binding = Binding(client=client, config=client._config, permission_cap=PermissionLevel.READ)
        writers = [
            t
            for t in self.mcp._tool_manager.list_tools()
            if t.fn._required_permission is not PermissionLevel.READ  # type: ignore[attr-defined]
        ]
        assert {"update_collective_page", "create_collective_page", "upload_file", "create_share"} <= {
            t.name for t in writers
        }
        with bind(binding):
            for tool in writers:
                with pytest.raises(PermissionDeniedError):
                    await tool.fn()
        assert calls == []

    async def test_gate_refuses_writes_even_inside_the_path_prefixes(self) -> None:
        # Defence in depth behind the cap: a login with a collectives group never writes, not even in
        # its own folders (Allgemein is writable for the group in Nextcloud).
        calls: list[tuple[str, str]] = []
        client = scoped_client(calls)
        for call in [
            client.dav_put("Allgemein/neu.md", b"x"),
            client.dav_delete("Allgemein/Satzung.md"),
            client.dav_mkcol("Allgemein/Neu"),
            client.dav_move("Allgemein/a.md", "Allgemein/b.md"),
        ]:
            with pytest.raises(NextcloudError) as err:
                await call
            assert err.value.status_code == 403
        assert calls == []
        await client.dav_get("Allgemein/Satzung.md")
        assert calls == [("GET", f"{FILES}/Allgemein/Satzung.md")]

    async def test_path_only_login_keeps_its_writes(self) -> None:
        client = NextcloudClient(
            Config(nextcloud_url=BASE, user="writer", password="pw", is_app_password=True, path_prefixes=("Shared",))
        )
        session = AsyncMock()
        resp = niquests.Response()
        resp.status_code = 201
        resp._content = b""
        session.request = AsyncMock(return_value=resp)
        client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
        await client.dav_put("Shared/a.md", b"x")
        session.request.assert_awaited()
