"""Per-request collectives group (X-Nextcloud-MCP-Collectives-Group, multi-user mode).

A person's own login, sent with the header, reaches only the collectives whose team has that
group as a direct member: read and write (create, change, move, trash, delete pages), with the
collective's files, and nothing else of Nextcloud. Same rule and lookup as the service account's
collectives_group (collectives_scope.py); the person's own rights in Nextcloud still apply.
"""

import base64
import json
from typing import Any
from unittest.mock import AsyncMock

import niquests
import pytest

import nc_mcp_server.state as state_module
from nc_mcp_server.client import NextcloudClient, NextcloudError
from nc_mcp_server.collectives_scope import ScopeView, check_collectives_request, parse_group_header
from nc_mcp_server.config import Config
from nc_mcp_server.login_paths import PathNotAllowedError
from nc_mcp_server.multiuser import Binding, ClientPool, Credentials, MultiUserAuthMiddleware, bind
from nc_mcp_server.permissions import PermissionLevel
from nc_mcp_server.server import create_server

BASE = "http://nc.invalid"
USER = "max"
API = f"{BASE}/ocs/v2.php/apps/collectives/api/v1.0"
FILES = f"{BASE}/remote.php/dav/files/{USER}"
GROUP = {"userId": "Mitglieder", "userType": 2, "status": "Member", "level": 1}
# Fictitious: 1 and 3 are shared with the group, 2 only with a board team.
COLLECTIVES = [
    {"id": 1, "name": "Vereinswiki", "circleId": "c1", "canEdit": True},
    {"id": 2, "name": "Vorstand intern", "circleId": "c2", "canEdit": True},
    {"id": 3, "name": "Projekte", "circleId": "c3", "canEdit": True},
]
MEMBERS = {"c1": [GROUP], "c2": [{"userId": "Vorstand", "userType": 2, "status": "Member", "level": 1}], "c3": [GROUP]}
FOLDERS = {1: "Kollektive/Vereinswiki", 2: "Kollektive/Vorstand intern", 3: "Kollektive/Projekte"}


def ocs(data: Any, status: int = 200) -> niquests.Response:
    r = niquests.Response()
    r.status_code = status
    r._content = json.dumps({"ocs": {"meta": {"statuscode": status, "message": ""}, "data": data}}).encode()
    return r


def page(cid: int, pid: int, title: str = "Seite") -> dict[str, Any]:
    return {
        "id": pid,
        "title": title,
        "parentId": 10 * cid,
        "collectivePath": FOLDERS[cid],
        "filePath": "",
        "fileName": f"{title}.md",
    }


def person_client(calls: list[tuple[str, str]]) -> NextcloudClient:
    client = NextcloudClient(Config(nextcloud_url=BASE, user=USER, password="pw", is_app_password=True))

    async def request(method: str, url: str, **kwargs: Any) -> niquests.Response:
        calls.append((method, url))
        path = url.split("/ocs/v2.php/", 1)[-1]
        parts = path.split("/")
        if path == "apps/collectives/api/v1.0/collectives":
            return ocs({"collectives": COLLECTIVES})
        if path.startswith("apps/circles/circles/"):
            return ocs(MEMBERS[parts[3]])
        if path.startswith("apps/collectives/api/v1.0/collectives/"):
            cid = int(parts[5])
            if path.endswith("/pages") and method == "GET":
                return ocs({"pages": [page(cid, 10 * cid, "Readme"), page(cid, 11 * cid)]})
            pid = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 11
            return ocs({"page": page(cid, pid)})
        r = niquests.Response()
        r.status_code = 201
        r._content = b""
        return r

    session = AsyncMock()
    session.request = AsyncMock(side_effect=request)
    client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
    return client


def binding(
    client: NextcloudClient, group: str | None = "Mitglieder", cap: PermissionLevel = PermissionLevel.DESTRUCTIVE
) -> Binding:
    return Binding(client=client, config=client._config, permission_cap=cap, collectives_group=group)


class TestHeader:
    def test_parse(self) -> None:
        assert parse_group_header(None) is None
        assert parse_group_header("Mitglieder") == "Mitglieder"
        for bad in ["", "  ", "Mit\nglieder", "x" * 256, "Mitglieder\x7f"]:
            with pytest.raises(ValueError, match="Collectives-Group"):
                parse_group_header(bad)

    async def test_middleware_sets_the_group_and_refuses_bad_values(self) -> None:
        seen: list[Binding] = []
        sent: list[dict[str, Any]] = []

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            seen.append(scope["state"]["nc_mcp_binding"])

        async def lookup(base: Config, creds: Credentials) -> str:
            return creds.login

        async def send(msg: dict[str, Any]) -> None:
            sent.append(msg)

        cfg = Config(nextcloud_url=BASE, multiuser=True, permission_level=PermissionLevel.DESTRUCTIVE)
        mw = MultiUserAuthMiddleware(app, ClientPool(cfg, lookup=lookup), PermissionLevel.DESTRUCTIVE)
        auth = (b"authorization", b"Basic " + base64.b64encode(b"max:pw"))
        await mw(
            {
                "type": "http",
                "method": "POST",
                "headers": [auth, (b"x-nextcloud-mcp-collectives-group", b"Mitglieder")],
            },
            AsyncMock(),
            send,
        )
        await mw({"type": "http", "method": "POST", "headers": [auth]}, AsyncMock(), send)
        assert [b.collectives_group for b in seen] == ["Mitglieder", None]
        twice = [
            auth,
            (b"x-nextcloud-mcp-collectives-group", b"Mitglieder"),
            (b"x-nextcloud-mcp-collectives-group", b"Vorstand"),
        ]
        await mw({"type": "http", "method": "POST", "headers": twice}, AsyncMock(), send)
        await mw(
            {"type": "http", "method": "POST", "headers": [auth, (b"x-nextcloud-mcp-collectives-group", b"  ")]},
            AsyncMock(),
            send,
        )
        assert [m["status"] for m in sent if m["type"] == "http.response.start"] == [400, 400]
        assert len(seen) == 2
        await mw.pool.close()


class TestWriteGate:
    view = ScopeView(ids=frozenset({1, 3}), prefixes=("Kollektive/Vereinswiki", "Kollektive/Projekte"))

    def check(self, method: str, path: str, writable: bool = True) -> None:
        check_collectives_request(method, f"{API}/{path}", base_url=BASE, view=self.view, writable=writable)

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("POST", "collectives/1/pages/10"),
            ("PUT", "collectives/1/pages/11"),
            ("PUT", "collectives/1/pages/11/emoji"),
            ("PUT", "collectives/1/pages/11/to/3"),
            ("GET", "collectives/1/pages/11/touch"),
            ("DELETE", "collectives/1/pages/11"),
            ("DELETE", "collectives/3/pages/trash/33"),
        ],
    )
    def test_writes_inside_the_group(self, method: str, path: str) -> None:
        self.check(method, path)
        with pytest.raises(PathNotAllowedError):
            self.check(method, path, writable=False)

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("POST", "collectives/2/pages/20"),
            ("PUT", "collectives/1/pages/11/to/2"),
            ("PUT", "collectives/2/pages/21/to/1"),
            ("DELETE", "collectives/2/pages/21"),
            ("POST", "collectives"),
            ("DELETE", "collectives/1"),
            ("POST", "collectives/1/shares"),
            ("PUT", "collectives/1/tags/4"),
            ("PATCH", "collectives/1/pages/trash/11"),
            ("DELETE", "collectives/trash/1"),
            ("POST", "collectives/1/pages/10/shares"),
        ],
    )
    def test_refused(self, method: str, path: str) -> None:
        with pytest.raises(PathNotAllowedError):
            self.check(method, path)


class TestPersonWithGroup:
    @pytest.fixture(autouse=True)
    def _server(self) -> Any:
        self.mcp = create_server(
            Config(nextcloud_url=BASE, multiuser=True, permission_level=PermissionLevel.DESTRUCTIVE)
        )
        yield
        state_module.set_state(None, Config())

    async def call(self, client: NextcloudClient, tool: str, group: str | None = "Mitglieder", **args: Any) -> Any:
        with bind(binding(client, group)):
            return json.loads(await self.mcp._tool_manager.call_tool(tool, args))

    async def test_create_and_update_in_a_group_collective_with_own_login(self) -> None:
        calls: list[tuple[str, str]] = []
        c = person_client(calls)
        out = await self.call(c, "create_collective_page", collective_id=1, parent_id=10, title="Neu", content="Hallo")
        assert out["id"] == 10
        assert ("POST", f"{API}/collectives/1/pages/10") in calls
        assert ("PUT", f"{FILES}/Kollektive/Vereinswiki/Seite.md") in calls
        await self.call(c, "update_collective_page", collective_id=3, page_id=33, title="Umbenannt")
        assert ("PUT", f"{API}/collectives/3/pages/33") in calls

    async def test_other_collectives_refused_before_sending(self) -> None:
        calls: list[tuple[str, str]] = []
        c = person_client(calls)
        cases: list[tuple[str, dict[str, Any]]] = [
            ("create_collective_page", {"collective_id": 2, "parent_id": 20, "title": "x"}),
            ("update_collective_page", {"collective_id": 2, "page_id": 21, "content": "x"}),
            ("get_collective_page", {"collective_id": 2, "page_id": 21}),
            ("trash_collective_page", {"collective_id": 2, "page_id": 21}),
            ("move_collective_page", {"collective_id": 1, "page_id": 11, "parent_id": 0, "to_collective_id": 2}),
            ("move_collective_page", {"collective_id": 2, "page_id": 21, "parent_id": 0, "to_collective_id": 1}),
        ]
        for tool, args in cases:
            with pytest.raises(Exception, match="not available"):
                with bind(binding(c)):
                    await self.mcp._tool_manager.call_tool(tool, args)
        assert not any("/collectives/2/pages/" in u or u.endswith("/to/2") for _, u in calls)
        assert not any("Vorstand" in u for _, u in calls)

    async def test_move_between_group_collectives(self) -> None:
        calls: list[tuple[str, str]] = []
        c = person_client(calls)
        await self.call(c, "move_collective_page", collective_id=1, page_id=11, parent_id=0, to_collective_id=3)
        assert ("PUT", f"{API}/collectives/1/pages/11/to/3") in calls

    async def test_lists_only_the_group(self) -> None:
        c = person_client([])
        out = await self.call(c, "list_collectives")
        assert [x["id"] for x in out["data"]] == [1, 3]

    async def test_nothing_else_of_nextcloud(self) -> None:
        calls: list[tuple[str, str]] = []
        c = person_client(calls)
        with bind(binding(c)):
            for call in [
                c.dav_get("Documents/geheim.md"),
                c.ocs_get("cloud/users"),
                c.dav_put("Allgemein/x.md", b"x"),
                c.dav_delete("Kollektive/Vereinswiki/Seite.md"),
            ]:
                with pytest.raises(NextcloudError) as err:
                    await call
                assert err.value.status_code == 403
        assert not any("geheim" in u or "cloud/users" in u or "Allgemein" in u for _, u in calls)

    async def test_without_header_the_login_is_unchanged(self) -> None:
        calls: list[tuple[str, str]] = []
        c = person_client(calls)
        out = await self.call(c, "list_collectives", group=None)
        assert [x["id"] for x in out["data"]] == [1, 2, 3]
        with bind(binding(c, None)):
            await self.mcp._tool_manager.call_tool("get_collective_page", {"collective_id": 2, "page_id": 21})
        assert ("GET", f"{API}/collectives/2/pages/21") in calls

    async def test_permission_cap_still_applies(self) -> None:
        c = person_client([])
        with bind(binding(c, cap=PermissionLevel.READ)), pytest.raises(Exception, match="requires 'write'"):
            await self.mcp._tool_manager.call_tool(
                "create_collective_page", {"collective_id": 1, "parent_id": 10, "title": "x"}
            )


class TestServiceAccountStaysReadOnly:
    async def test_header_does_not_open_writes_for_the_scoped_service_account(self) -> None:
        client = NextcloudClient(
            Config(
                nextcloud_url=BASE,
                user="bot",
                password="pw",
                is_app_password=True,
                path_prefixes=("Allgemein",),
                collectives_group="Mitglieder",
            )
        )
        session = AsyncMock()
        client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
        with bind(binding(client)):
            for call in [
                client.ocs_post_json("apps/collectives/api/v1.0/collectives/1/pages/10", {"title": "x"}),
                client.dav_put("Kollektive/Vereinswiki/x.md", b"x"),
            ]:
                with pytest.raises(NextcloudError):
                    await call
        session.request.assert_not_awaited()

    async def test_other_group_than_configured_reaches_no_collectives(self) -> None:
        client = NextcloudClient(
            Config(
                nextcloud_url=BASE,
                user="bot",
                password="pw",
                is_app_password=True,
                path_prefixes=("Allgemein",),
                collectives_group="Mitglieder",
            )
        )
        session = AsyncMock()
        client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
        with bind(binding(client, group="Vorstand")), pytest.raises(NextcloudError):
            await client.ocs_get("apps/collectives/api/v1.0/collectives")
        session.request.assert_not_awaited()
