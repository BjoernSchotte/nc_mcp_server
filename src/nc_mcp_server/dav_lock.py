"""Explain a WebDAV lock (HTTP 423) instead of a bare "Locked".

Nextcloud's file locking (files_lock, used by the Text editor and by WebDAV LOCK) exposes the
holder as properties of the file: nc:lock, nc:lock-owner-type (0 user, 1 app, 2 token),
nc:lock-owner-displayname, nc:lock-owner-editor (app id), nc:lock-time (epoch seconds) and
nc:lock-timeout (seconds, 0 = no expiry). After a 423 the client reads them with PROPFIND
Depth 0 (a read, allowed wherever the file may be read) and raises one clear message.

No automatic retry: an editor lock lasts as long as an editor session is open, so a retry after
a few seconds almost never succeeds and a second write attempt only hides the reason.
"""

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

NC = "http://nextcloud.org/ns"
LOCK_PROPS = ("lock", "lock-owner-type", "lock-owner-displayname", "lock-owner-editor", "lock-time", "lock-timeout")
LOCK_PROPFIND_BODY = (
    '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:nc="http://nextcloud.org/ns"><d:prop>'
    + "".join(f"<nc:{p}/>" for p in LOCK_PROPS)
    + "</d:prop></d:propfind>"
)
# An app lock without expiry older than this is probably left over (editor gone without unlocking).
ORPHANED_AFTER_S = 30 * 60
_APP_NAMES = {"text": "the Text editor", "richdocuments": "Nextcloud Office", "onlyoffice": "ONLYOFFICE"}


def parse_lock_props(xml: str) -> dict[str, str]:
    """The nc:lock* properties of a PROPFIND Depth 0 answer (only those with a value)."""
    try:
        root = ET.fromstring(xml)  # noqa: S314 (answer of the configured Nextcloud)
    except ET.ParseError:
        return {}
    out: dict[str, str] = {}
    for prop in LOCK_PROPS:
        el = root.find(f".//{{{NC}}}{prop}")
        if el is not None and el.text and el.text.strip():
            out[prop] = el.text.strip()
    return out


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _holder(props: dict[str, str]) -> str:
    kind = _int(props.get("lock-owner-type"))
    if kind == 0:
        name = props.get("lock-owner-displayname", "")
        # Never an e-mail address; a display name only for a user lock.
        return f"{name} (user lock)" if name and "@" not in name else "another user (user lock)"
    if kind == 1:
        editor = props.get("lock-owner-editor", "")
        app = _APP_NAMES.get(editor) or (f"the app '{editor}'" if editor.replace("_", "").isalnum() else "an app")
        return f"{app} (app lock)"
    if kind == 2:
        return "a WebDAV client (token lock)"
    return "an unknown holder"


def describe_lock(path: str, props: dict[str, str], *, now: float, timezone: str = "") -> str:
    """One message for a 423 on ``path`` from its lock properties (empty: holder unknown)."""
    if props.get("lock") != "1":
        return f"'{path}' is locked (HTTP 423); who holds the lock could not be read. Do not retry blindly."
    tz = ZoneInfo(timezone) if timezone else UTC
    tz_name = timezone or "UTC"
    since = _int(props.get("lock-time"))
    timeout = _int(props.get("lock-timeout")) or 0
    kind = _int(props.get("lock-owner-type"))
    parts = [f"'{path}' is locked by {_holder(props)}"]
    if since is not None:
        parts.append(f"since {datetime.fromtimestamp(since, tz).strftime('%Y-%m-%d %H:%M')} {tz_name}")
    if timeout > 0 and since is not None:
        end = datetime.fromtimestamp(since + timeout, tz)
        # Date only when the lock does not end today (in the configured zone).
        fmt = "%H:%M" if end.date() == datetime.fromtimestamp(now, tz).date() else "%Y-%m-%d %H:%M"
        parts.append(f"until {end.strftime(fmt)} {tz_name}")
    else:
        parts.append("without expiry")
    text = ", ".join(parts) + "."
    if kind == 1:
        text += (
            " The lock ends when every open editor session of this file (browser tabs, apps, other devices)"
            " is closed. If it stays, Nextcloud's background jobs (cron) clear it; an admin can check them."
        )
        if timeout == 0 and since is not None and now - since > ORPHANED_AFTER_S:
            minutes = int((now - since) // 60)
            text += f" It has been held for {minutes} minutes: probably orphaned, check the background jobs."
    elif kind == 0:
        text += " Ask the holder to unlock or close the file, or wait until the lock expires."
    elif kind == 2:
        text += " The WebDAV client that took it must unlock it, or wait until it expires."
    return text + " Not retried."
