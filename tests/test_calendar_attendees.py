"""Unit tests for attendees: parsing, setting the guest list, organizer, result and link."""

import base64
from datetime import date, datetime
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from icalendar import Calendar as ICal

from nc_mcp_server.tools import calendar as cal_mod
from nc_mcp_server.tools.calendar import (
    _attendee_emails,
    _build_ical,
    _event_link,
    _event_result,
    _organizer_email,
    _parse_attendees,
    _set_attendees,
    _vevent,
)

ME = ("bjoern@example.org", "Björn")


@pytest.fixture(autouse=True)
def _config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cal_mod, "get_config", lambda: SimpleNamespace(user="bjoern", nextcloud_url="https://cloud.example.org")
    )


def _event(attendees: list[tuple[str, str]] | None = None) -> str:
    return _build_ical(
        "uid-1",
        "CoP Treffen",
        datetime(2026, 10, 15, 13, 0, tzinfo=ZoneInfo("Europe/Berlin")),
        datetime(2026, 10, 15, 16, 0, tzinfo=ZoneInfo("Europe/Berlin")),
        created_by="bjoern",
        attendees=attendees,
        organizer=ME if attendees else None,
    )


class TestParseAttendees:
    def test_plain_named_and_mailto(self) -> None:
        got = _parse_attendees("a@x.org, Karl Muster <Karl@Y.de>; mailto:c@z.org\n")
        assert got == [("a@x.org", ""), ("karl@y.de", "Karl Muster"), ("c@z.org", "")]

    def test_dedupes_case_insensitive(self) -> None:
        assert _parse_attendees("A@x.org, a@X.org") == [("a@x.org", "")]

    @pytest.mark.parametrize(
        "bad", ["karl", "a@b", "a b@x.org", "a@x.org\r\nBCC: e@vil.org", "<>", "a@-x.org", "a\x01b@x.org", "ä@x.org"]
    )
    def test_rejects_invalid(self, bad: str) -> None:
        with pytest.raises(ValueError, match="Invalid attendee"):
            _parse_attendees(f"ok@x.org, {bad}")

    def test_limit(self) -> None:
        with pytest.raises(ValueError, match="At most"):
            _parse_attendees(",".join(f"u{i}@x.org" for i in range(101)))


class TestSetAttendees:
    def test_create_sets_organizer_and_needs_action(self) -> None:
        comp = _vevent(ICal.from_ical(_event([("karl@y.de", "Karl"), ("a@x.org", "")])))
        assert _attendee_emails(comp) == ["karl@y.de", "a@x.org"]
        assert _organizer_email(comp) == "bjoern@example.org"
        karl = comp.get("ATTENDEE")[0]
        assert karl.params["PARTSTAT"] == "NEEDS-ACTION"
        assert karl.params["RSVP"] == "TRUE"
        assert karl.params["CN"] == "Karl"

    def test_replace_keeps_replies_of_kept_guests(self) -> None:
        cal = ICal.from_ical(_event([("karl@y.de", "Karl"), ("a@x.org", "")]))
        comp = _vevent(cal)
        comp.get("ATTENDEE")[1].params["PARTSTAT"] = "ACCEPTED"
        _set_attendees(comp, [("a@x.org", ""), ("neu@x.org", "Neu")], ME)
        assert _attendee_emails(comp) == ["a@x.org", "neu@x.org"]
        props = comp.get("ATTENDEE")
        assert props[0].params["PARTSTAT"] == "ACCEPTED"
        assert props[1].params["PARTSTAT"] == "NEEDS-ACTION"
        assert _organizer_email(comp) == "bjoern@example.org"

    def test_organizer_never_attendee_and_single_attendee_roundtrip(self) -> None:
        cal = ICal.from_ical(_event([("bjoern@example.org", ""), ("a@x.org", "")]))
        comp = _vevent(ICal.from_ical(cal.to_ical()))
        assert _attendee_emails(comp) == ["a@x.org"]

    def test_clear(self) -> None:
        comp = _vevent(ICal.from_ical(_event([("a@x.org", "")])))
        _set_attendees(comp, [], ME)
        assert _attendee_emails(comp) == []


class TestResultAndLink:
    def test_result_shows_ten_and_count_and_link(self) -> None:
        guests = [(f"u{i}@x.org", "") for i in range(12)]
        path = "calendars/bjoern/it-verband/uid-1.ics"
        res = _event_result(_event(guests), path)
        assert res["attendees"] == [f"u{i}@x.org" for i in range(10)]
        assert res["attendee_count"] == 12
        assert res["organizer"] == "bjoern@example.org"
        assert res["summary"] == "CoP Treffen"
        obj = base64.b64encode(b"/remote.php/dav/calendars/bjoern/it-verband/uid-1.ics").decode()
        assert res["link"] == f"https://cloud.example.org/apps/calendar/dayGridMonth/2026-10-15/edit/sidebar/{obj}/next"

    def test_link_from_full_href_and_all_day(self) -> None:
        link = _event_link("/remote.php/dav/calendars/bjoern/p/x.ics", SimpleNamespace(dt=date(2026, 12, 24)))
        obj = base64.b64encode(b"/remote.php/dav/calendars/bjoern/p/x.ics").decode()
        assert link.endswith(f"/dayGridMonth/2026-12-24/edit/sidebar/{obj}/next")

    def test_without_guests(self) -> None:
        res = _event_result(_event(), "calendars/bjoern/p/uid-1.ics")
        assert res["attendees"] == []
        assert res["attendee_count"] == 0
        assert "organizer" not in res


class TestNames:
    def test_backslash_del_and_separators_dropped(self) -> None:
        got = _parse_attendees("Karl\\ <k@x.org>, An\x7fna\u2028 <a@x.org>")
        assert got == [("k@x.org", "Karl"), ("a@x.org", "Anna")]

    def test_cn_with_cleaned_name_roundtrips(self) -> None:
        cal = ICal.from_ical(_event(_parse_attendees("Karl\\ <k@x.org>")))
        again = _vevent(ICal.from_ical(cal.to_ical()))
        prop = again.get("ATTENDEE")
        assert str(prop.params["CN"]) == "Karl"
        assert prop.params["CUTYPE"] == "INDIVIDUAL"

    def test_single_existing_attendee_keeps_reply_on_replace(self) -> None:
        cal = ICal.from_ical(_event([("a@x.org", "")]))
        comp = _vevent(ICal.from_ical(cal.to_ical()))
        comp.get("ATTENDEE").params["PARTSTAT"] = "ACCEPTED"
        _set_attendees(comp, [("a@x.org", ""), ("b@x.org", "")], ME)
        assert [str(p.params["PARTSTAT"]) for p in comp.get("ATTENDEE")] == ["ACCEPTED", "NEEDS-ACTION"]
