"""Path limits per login (NEXTCLOUD_MCP_LOGIN_PATHS, multi-user mode).

A restricted login reaches only WebDAV files below its prefixes; everything else is refused
before a request is sent. Other logins are unaffected; without the variable nothing changes.
"""

import json
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, patch

import niquests
import pytest

import nc_mcp_server.state as state_module

from nc_mcp_server.client import NextcloudClient, NextcloudError
from nc_mcp_server.config import Config
from nc_mcp_server.login_paths import (
    PathNotAllowedError,
    check_path,
    check_request,
    inside,
    normalize,
    parse_login_paths,
    prefixes_for,
)
from nc_mcp_server.multiuser import Binding, ClientPool, Credentials, bind
from nc_mcp_server.permissions import PermissionLevel
from nc_mcp_server.server import create_server

PREFIXES = ("Allgemein",)
BASE = "http://nc.invalid"


def restricted_client(user: str = "itverband-claw-bot", prefixes: tuple[str, ...] | None = PREFIXES) -> NextcloudClient:
    return NextcloudClient(
        Config(nextcloud_url=BASE, user=user, password="pw", is_app_password=True, path_prefixes=prefixes)
    )


def ok_response(status: int = 207, text: str = "") -> niquests.Response:
    r = niquests.Response()
    r.status_code = status
    r._content = text.encode("utf-8")
    return r


def mock_send(client: NextcloudClient, status: int = 207, text: str = "") -> AsyncMock:
    """Session below the client: the returned mock is what would reach Nextcloud."""
    session = AsyncMock()
    session.request = AsyncMock(return_value=ok_response(status, text))
    client._get_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
    return session.request


class TestNormalize:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Allgemein", "Allgemein"),
            ("/Allgemein//Satzung/", "Allgemein/Satzung"),
            ("Allgemein/Ünï.pdf", "Allgemein/Ünï.pdf"),
            ("Allgemein/Über.pdf", "Allgemein/Über.pdf"),  # NFC
            ("", ""),
        ],
    )
    def test_ok(self, raw: str, expected: str) -> None:
        assert normalize(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "Allgemein/../Vorstand",
            "./Allgemein",
            "Allgemein/.",
            "Allgemein/%2e%2e/Vorstand",
            "Allgemein\\..\\Vorstand",
            "Allgemein/\x00x",
            "Allgemein/ /x",
            "a" * 5000,
        ],
    )
    def test_refused(self, raw: str) -> None:
        assert normalize(raw) is None

    def test_inside_by_whole_segments(self) -> None:
        assert inside("Allgemein", PREFIXES)
        assert inside("Allgemein/a/b.pdf", PREFIXES)
        assert not inside("Allgemeines/x.pdf", PREFIXES)
        assert not inside("Vorstand/x.pdf", PREFIXES)

    def test_check_path(self) -> None:
        assert check_path("/Allgemein/x.md", PREFIXES) == "Allgemein/x.md"
        for p in ["/", "", "Vorstand/x.md", "Allgemein/../Vorstand/x.md"]:
            with pytest.raises(PathNotAllowedError):
                check_path(p, PREFIXES)


class TestParse:
    def test_valid(self) -> None:
        assert parse_login_paths('{"bot": ["/Allgemein/", "Allgemein", "Docs/Public"]}') == {
            "bot": ("Allgemein", "Docs/Public")
        }
        assert parse_login_paths("") == {}
        assert parse_login_paths("   ") == {}

    @pytest.mark.parametrize(
        "raw",
        [
            "{",
            "[]",
            '{"bot": []}',
            '{"bot": "Allgemein"}',
            '{"": ["A"]}',
            '{"bot": ["/"]}',
            '{"bot": ["A/../B"]}',
            '{"bot": ["A%2e"]}',
            '{"bot": [1]}',
        ],
    )
    def test_invalid(self, raw: str) -> None:
        with pytest.raises(ValueError, match="NEXTCLOUD_MCP_LOGIN_PATHS"):
            parse_login_paths(raw)

    def test_from_env_and_validate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEXTCLOUD_URL", BASE)
        monkeypatch.setenv("NEXTCLOUD_MCP_MULTIUSER", "true")
        monkeypatch.setenv("NEXTCLOUD_MCP_LOGIN_PATHS", json.dumps({"bot": ["Allgemein"]}))
        monkeypatch.delenv("NEXTCLOUD_USER", raising=False)
        monkeypatch.delenv("NEXTCLOUD_PASSWORD", raising=False)
        cfg = Config.from_env()
        cfg.validate()
        assert cfg.login_paths == {"bot": ("Allgemein",)}
        monkeypatch.setenv("NEXTCLOUD_MCP_LOGIN_PATHS", "{kaputt")
        with pytest.raises(ValueError, match="not valid JSON"):
            Config.from_env()

    def test_case_duplicates_refused(self) -> None:
        with pytest.raises(ValueError, match="listed twice"):
            parse_login_paths('{"Bot": ["A"], "bot": ["B"]}')

    def test_needs_multiuser(self) -> None:
        with pytest.raises(ValueError, match="needs NEXTCLOUD_MCP_MULTIUSER"):
            Config(nextcloud_url=BASE, user="u", password="p", login_paths={"u": ("A",)}).validate()


class TestCheckRequest:
    files = f"{BASE}/remote.php/dav/files/itverband-claw-bot"

    def check(self, method: str, url: str, headers: dict[str, str] | None = None) -> None:
        check_request(method, url, headers, base_url=BASE, dav_user="itverband-claw-bot", prefixes=PREFIXES)

    def test_files_inside(self) -> None:
        self.check("PROPFIND", f"{self.files}/Allgemein/")
        self.check("GET", f"{self.files}/Allgemein/Satzung/Satzung%202025.pdf")
        self.check("COPY", f"{self.files}/Allgemein/a", {"Destination": f"{self.files}/Allgemein/b"})

    @pytest.mark.parametrize(
        ("method", "url", "headers"),
        [
            ("GET", f"{files}/Vorstand/x.md", None),
            ("PROPFIND", f"{files}/", None),
            ("GET", f"{files}/Allgemein/%2e%2e/Vorstand/x.md", None),
            ("GET", f"{files}/Allgemein/..%2fVorstand/x.md", None),
            ("GET", f"{files}/Allgemein/%252e%252e/x", None),
            ("GET", f"{files}/Allgemeines/x.md", None),
            ("GET", f"{BASE}/remote.php/dav/files/other-user/Allgemein/x.md", None),
            ("GET", f"{files}/Allgemein/x.md?download=1", None),
            ("GET", "http://evil.invalid/remote.php/dav/files/itverband-claw-bot/Allgemein/x.md", None),
            ("MOVE", f"{files}/Allgemein/x.md", {"Destination": f"{files}/Vorstand/x.md"}),
            ("GET", f"{BASE}/ocs/v2.php/cloud/user", None),
            ("POST", f"{BASE}/ocs/v2.php/apps/files_sharing/api/v1/shares", None),
            ("PROPFIND", f"{BASE}/remote.php/dav/calendars/itverband-claw-bot/", None),
            ("PROPFIND", f"{BASE}/remote.php/dav/trashbin/itverband-claw-bot/trash/", None),
            ("REPORT", f"{files}/Allgemein/", None),
            ("SEARCH", f"{files}/Allgemein/", None),
        ],
    )
    def test_refused(self, method: str, url: str, headers: dict[str, str] | None) -> None:
        with pytest.raises(PathNotAllowedError):
            self.check(method, url, headers)


class TestClient:
    async def test_inside_is_sent(self) -> None:
        c = restricted_client()
        send = mock_send(c, 200, "inhalt")
        content, _ = await c.dav_get("Allgemein/Test.md")
        assert content == b"inhalt"
        assert send.await_count == 1

    @pytest.mark.parametrize(
        "path", ["Vorstand/x.md", "/", "Allgemein/../Vorstand/x.md", "Allgemein/%2e%2e/Vorstand/x.md"]
    )
    async def test_outside_never_sent(self, path: str) -> None:
        c = restricted_client()
        send = mock_send(c)
        with pytest.raises(NextcloudError) as err:
            await c.dav_get(path)
        assert err.value.status_code == 403
        send.assert_not_awaited()

    async def test_ocs_never_sent_also_fresh_login(self) -> None:
        c = restricted_client()
        send = mock_send(c)
        session = AsyncMock()
        with patch.object(NextcloudClient, "_build_session", return_value=session):
            for call in (
                lambda: c.ocs_get("/ocs/v2.php/cloud/user"),
                lambda: c.ocs_get("/ocs/v2.php/cloud/user", fresh_login=True),
                lambda: c.ocs_delete("/ocs/v2.php/apps/x", fresh_login=True),
            ):
                with pytest.raises(NextcloudError) as err:
                    await call()
                assert err.value.status_code == 403
        send.assert_not_awaited()
        session.request.assert_not_awaited()

    async def test_fresh_login_path_checked_too(self) -> None:
        c = restricted_client()
        session = AsyncMock()
        with patch.object(NextcloudClient, "_build_session", return_value=session):
            with pytest.raises(NextcloudError):
                await c._request_with_password("GET", f"{BASE}/ocs/v2.php/cloud/user")
        session.request.assert_not_awaited()

    async def test_move_destination_checked(self) -> None:
        c = restricted_client()
        send = mock_send(c, 201)
        with pytest.raises(NextcloudError):
            await c.dav_move("Allgemein/a.md", "Vorstand/a.md")
        send.assert_not_awaited()

    async def test_unrestricted_client_unchanged(self) -> None:
        c = restricted_client(user="alice", prefixes=None)
        send = mock_send(c, 200, "x")
        await c.dav_get("Vorstand/x.md")
        assert send.await_count == 1


class TestPool:
    async def test_prefixes_by_login(self) -> None:
        async def lookup(base: Config, creds: Credentials) -> str:
            return "uid-" + creds.login

        cfg = Config(
            nextcloud_url=BASE,
            multiuser=True,
            permission_level=PermissionLevel.READ,
            login_paths={"itverband-claw-bot": ("Allgemein",)},
        )
        pool = ClientPool(cfg, lookup=lookup)
        _, bot = await pool.get(Credentials("itverband-claw-bot", "pw"))
        _, alice = await pool.get(Credentials("alice", "pw"))
        assert bot.path_prefixes == ("Allgemein",)
        assert alice.path_prefixes is None
        await pool.close()


def _search_xml(*paths: str) -> str:
    resp = "".join(
        f"<d:response><d:href>/remote.php/dav/files/itverband-claw-bot/{p}</d:href><d:propstat><d:prop><d:resourcetype/></d:prop>"
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        for p in paths
    )
    return f'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">{resp}</d:multistatus>'


class TestSearchTool:
    @pytest.fixture(autouse=True)
    def _server(self) -> Any:
        self.mcp = create_server(Config(nextcloud_url=BASE, multiuser=True, permission_level=PermissionLevel.READ))
        yield
        state_module.set_state(None, Config())

    def _search(self) -> Any:
        return self.mcp

    async def _call(self, mcp: Any, client: NextcloudClient, **args: Any) -> Any:
        config = client._config
        with bind(Binding(client=client, config=config)):
            return await mcp.call_tool("search_files", args)

    async def test_scope_must_be_inside(self) -> None:
        c = restricted_client()
        mock_send(c, 207, _search_xml())
        mcp = self._search()
        for path in ["/", "Vorstand", "Allgemein/../Vorstand"]:
            with pytest.raises(Exception, match="Search path not allowed"):
                await self._call(mcp, c, query="x", path=path)

    async def test_results_filtered(self) -> None:
        c = restricted_client()
        send = mock_send(c, 207, _search_xml("Allgemein/a.md", "Vorstand/geheim.md", "Allgemeines/b.md"))
        mcp = self._search()
        out = await self._call(mcp, c, query="a", path="Allgemein")
        text = json.dumps(out, default=str)
        assert "Allgemein/a.md" in text
        assert "Vorstand/geheim.md" not in text
        assert "Allgemeines/b.md" not in text
        assert send.await_args is not None
        body = send.await_args.kwargs["data"]
        assert "/files/itverband-claw-bot/Allgemein" in body


SEARCH_BODY = (
    '<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:"><d:basicsearch><d:from><d:scope>'
    "<d:href>/files/itverband-claw-bot/{scope}</d:href><d:depth>infinity</d:depth></d:scope></d:from>"
    "</d:basicsearch></d:searchrequest>"
)


class TestReviewFixes:
    async def test_streaming_upload_checked(self) -> None:
        c = restricted_client()
        session = AsyncMock()
        with patch.object(NextcloudClient, "_get_session", AsyncMock(return_value=session)):

            async def chunks() -> AsyncIterator[bytes]:
                yield b"x"

            with pytest.raises(NextcloudError) as err:
                await c.dav_put_stream("Vorstand/evil.txt", chunks)
            assert err.value.status_code == 403
        session.request.assert_not_awaited()

    def test_search_scope_from_body(self) -> None:
        def chk(body: object) -> None:
            check_request(
                "SEARCH",
                f"{BASE}/remote.php/dav/",
                None,
                base_url=BASE,
                dav_user="itverband-claw-bot",
                prefixes=PREFIXES,
                user="itverband-claw-bot",
                body=body,
            )

        chk(SEARCH_BODY.format(scope="Allgemein"))
        chk(SEARCH_BODY.format(scope="Allgemein/Satzung").encode())
        for bad in [
            SEARCH_BODY.format(scope=""),
            SEARCH_BODY.format(scope="Vorstand"),
            SEARCH_BODY.format(scope="Allgemein/../Vorstand"),
            "<x/>",
            None,
        ]:
            with pytest.raises(PathNotAllowedError):
                chk(bad)
        with pytest.raises(PathNotAllowedError):
            chk(SEARCH_BODY.format(scope="Allgemein").replace("itverband-claw-bot", "alice"))
        with pytest.raises(PathNotAllowedError):
            chk(SEARCH_BODY.format(scope="Allgemein/&#46;&#46;/Vorstand"))

    async def test_no_redirects_for_restricted(self) -> None:
        c = restricted_client()
        session = AsyncMock()
        session.request = AsyncMock(return_value=ok_response(200, "x"))
        with patch.object(NextcloudClient, "_get_session", AsyncMock(return_value=session)):
            await c.dav_get("Allgemein/x.md")
        assert session.request.await_args is not None
        assert session.request.await_args.kwargs["allow_redirects"] is False

    def test_scheme_compared(self) -> None:
        with pytest.raises(PathNotAllowedError):
            check_request(
                "GET",
                "https://nc.invalid/remote.php/dav/files/itverband-claw-bot/Allgemein/x",
                None,
                base_url=BASE,
                dav_user="itverband-claw-bot",
                prefixes=PREFIXES,
            )

    def test_prefixes_by_login_or_user_id_case_insensitive(self) -> None:
        lp = {"itverband-claw-bot": ("Allgemein",)}
        assert prefixes_for(lp, "itverband-claw-bot", "itverband-claw-bot") == ("Allgemein",)
        assert prefixes_for(lp, "Itverband-Claw-Bot", "itverband-claw-bot") == ("Allgemein",), "other case"
        assert prefixes_for(lp, "bot@example.org", "itverband-claw-bot") == ("Allgemein",), "e-mail login, same user ID"
        assert prefixes_for(lp, "alice", "alice") is None
        assert prefixes_for({}, "x", "y") is None
        both = {"bot@example.org": ("Allgemein/Satzung",), "itverband-claw-bot": ("Allgemein",)}
        assert prefixes_for(both, "bot@example.org", "itverband-claw-bot") == ("Allgemein/Satzung",), "stricter wins"
        disjoint = {"a": ("X",), "b": ("Y",)}
        p = prefixes_for(disjoint, "a", "b")
        assert p is not None
        assert not inside("X/1", p)
        assert not inside("Y/1", p)

    async def test_pool_uses_user_id(self) -> None:
        async def lookup(base: Config, creds: Credentials) -> str:
            return "itverband-claw-bot"

        cfg = Config(
            nextcloud_url=BASE,
            multiuser=True,
            permission_level=PermissionLevel.READ,
            login_paths={"itverband-claw-bot": ("Allgemein",)},
        )
        pool = ClientPool(cfg, lookup=lookup)
        _, c = await pool.get(Credentials("ITVERBAND-CLAW-BOT", "pw"))
        assert c.path_prefixes == ("Allgemein",)
        await pool.close()
