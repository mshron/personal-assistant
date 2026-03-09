"""Tests for the Gmail IMAP/SMTP sidecar proxy.

All IMAP and SMTP interactions are mocked -- no network access needed.
"""

from __future__ import annotations

import base64
import email
import json
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# We need to set env vars before importing the module
_ENV = {"GMAIL_ADDRESS": "test@gmail.com", "GMAIL_APP_PASSWORD": "test-password"}


@pytest.fixture(autouse=True)
def _set_env(monkeypatch):
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)


# Import after env is conceptually set, but we'll patch the module-level vars.
# We add the credential-proxy dir to sys.path so we can import the module.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "credential-proxy"))

import importlib

@pytest.fixture()
def proxy_module(monkeypatch):
    """Import (or re-import) the proxy module with env vars set."""
    for k, v in _ENV.items():
        monkeypatch.setenv(k, v)
    # Force re-import to pick up env vars
    mod_name = "gmail-imap-proxy"
    # Python doesn't allow hyphens in module names, so we load it manually.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gmail_imap_proxy",
        str(__import__("pathlib").Path(__file__).resolve().parent.parent / "credential-proxy" / "gmail-imap-proxy.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    # Patch env vars on the module after exec
    monkeypatch.setattr(mod, "GMAIL_ADDRESS", "test@gmail.com", raising=False)
    monkeypatch.setattr(mod, "GMAIL_APP_PASSWORD", "test-password", raising=False)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "GMAIL_ADDRESS", "test@gmail.com")
    monkeypatch.setattr(mod, "GMAIL_APP_PASSWORD", "test-password")
    # Reset global IMAP connection
    monkeypatch.setattr(mod, "_imap_conn", None)
    return mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_simple_email(
    from_addr: str = "alice@example.com",
    to_addr: str = "test@gmail.com",
    subject: str = "Test Subject",
    body: str = "Hello, world!",
    date: str = "Mon, 01 Mar 2026 10:00:00 +0000",
    list_unsub: str | None = None,
) -> bytes:
    """Build a simple RFC2822 email as bytes."""
    msg = MIMEText(body, "plain", "utf-8")
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = date
    if list_unsub:
        msg["List-Unsubscribe"] = list_unsub
    return msg.as_bytes()


def _make_multipart_email(
    from_addr: str = "alice@example.com",
    subject: str = "Multipart Test",
    text_body: str = "Plain text",
    html_body: str = "<p>HTML body</p>",
    date: str = "Mon, 01 Mar 2026 10:00:00 +0000",
) -> bytes:
    """Build a multipart/alternative email as bytes."""
    msg = MIMEMultipart("alternative")
    msg["From"] = from_addr
    msg["To"] = "test@gmail.com"
    msg["Subject"] = subject
    msg["Date"] = date
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg.as_bytes()


def _mock_imap(uids: list[bytes] | None = None, fetch_data: list | None = None):
    """Create a mock IMAP connection."""
    mock = MagicMock()
    mock.noop.return_value = ("OK", [b"NOOP completed"])
    mock.select.return_value = ("OK", [b"1"])

    if uids is not None:
        mock.uid.side_effect = _make_uid_side_effect(uids, fetch_data)
    return mock


def _make_uid_side_effect(uids: list[bytes], fetch_data: list | None = None):
    """Build a side_effect function for conn.uid() that handles SEARCH and FETCH."""
    fetch_map = {}
    if fetch_data:
        for uid, raw in fetch_data:
            fetch_map[uid] = raw

    def uid_handler(command, *args):
        if command == "SEARCH":
            return ("OK", [b" ".join(uids)])
        elif command == "FETCH":
            msg_uid = args[0]
            if isinstance(msg_uid, bytes):
                msg_uid = msg_uid.decode()
            raw = fetch_map.get(msg_uid, fetch_map.get(msg_uid.encode(), b""))
            if raw:
                return ("OK", [(b"1 (RFC822 {%d}" % len(raw), raw)])
            return ("OK", [None])
        return ("NO", [b"Unknown command"])

    return uid_handler


# ---------------------------------------------------------------------------
# Test: message list
# ---------------------------------------------------------------------------


class TestMessageList:
    def test_list_returns_correct_json(self, proxy_module):
        uids = [b"101", b"102", b"103"]
        mock_conn = _mock_imap(uids=uids)

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {
                "q": ["after:2026/03/01 before:2026/03/08"],
                "labelIds": ["INBOX"],
                "maxResults": ["500"],
            }
            status, data = proxy_module.handle_list(qs)

        assert status == 200
        assert len(data["messages"]) == 3
        assert data["messages"][0] == {"id": "101", "threadId": "101"}
        assert data["messages"][2] == {"id": "103", "threadId": "103"}
        assert data["resultSizeEstimate"] == 3

    def test_list_with_date_criteria_builds_imap_search(self, proxy_module):
        mock_conn = _mock_imap(uids=[])

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {
                "q": ["after:2026/03/01 before:2026/03/08"],
                "labelIds": ["INBOX"],
            }
            proxy_module.handle_list(qs)

        # Check the SEARCH call had correct IMAP date criteria
        mock_conn.uid.assert_called_once()
        call_args = mock_conn.uid.call_args
        assert call_args[0][0] == "SEARCH"
        criteria = call_args[0][2]
        assert "SINCE 01-Mar-2026" in criteria
        assert "BEFORE 08-Mar-2026" in criteria

    def test_list_respects_max_results(self, proxy_module):
        uids = [str(i).encode() for i in range(1, 20)]
        mock_conn = _mock_imap(uids=uids)

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {"q": [""], "labelIds": ["INBOX"], "maxResults": ["5"]}
            status, data = proxy_module.handle_list(qs)

        assert status == 200
        assert len(data["messages"]) == 5

    def test_list_maps_sent_label_to_imap_folder(self, proxy_module):
        mock_conn = _mock_imap(uids=[])

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {"q": [""], "labelIds": ["SENT"]}
            proxy_module.handle_list(qs)

        mock_conn.select.assert_called_with('"[Gmail]/Sent Mail"', readonly=True)

    def test_list_empty_returns_empty(self, proxy_module):
        mock_conn = _mock_imap(uids=[])

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            status, data = proxy_module.handle_list({"q": [""], "labelIds": ["INBOX"]})

        assert status == 200
        assert data["messages"] == []
        assert data["resultSizeEstimate"] == 0


# ---------------------------------------------------------------------------
# Test: get message (metadata)
# ---------------------------------------------------------------------------


class TestGetMetadata:
    def test_get_metadata_returns_requested_headers(self, proxy_module):
        raw = _make_simple_email(
            from_addr="alice@example.com",
            subject="Newsletter",
            date="Mon, 01 Mar 2026 10:00:00 +0000",
            list_unsub="<mailto:unsub@example.com>",
        )
        mock_conn = _mock_imap(uids=[b"101"], fetch_data=[("101", raw)])

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {
                "format": ["metadata"],
                "metadataHeaders": ["From", "Subject", "Date", "List-Unsubscribe"],
            }
            status, data = proxy_module.handle_get("101", qs)

        assert status == 200
        assert data["id"] == "101"
        assert data["internalDate"] == "1772359200000"

        headers = data["payload"]["headers"]
        header_names = [h["name"] for h in headers]
        assert "From" in header_names
        assert "Subject" in header_names
        assert "List-Unsubscribe" in header_names

        from_header = next(h for h in headers if h["name"] == "From")
        assert from_header["value"] == "alice@example.com"

    def test_get_metadata_excludes_unrequested_headers(self, proxy_module):
        raw = _make_simple_email(list_unsub="<mailto:unsub@example.com>")
        mock_conn = _mock_imap(uids=[b"101"], fetch_data=[("101", raw)])

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {"format": ["metadata"], "metadataHeaders": ["From"]}
            status, data = proxy_module.handle_get("101", qs)

        assert status == 200
        headers = data["payload"]["headers"]
        # Only From should be present
        assert len(headers) == 1
        assert headers[0]["name"] == "From"


# ---------------------------------------------------------------------------
# Test: get message (full)
# ---------------------------------------------------------------------------


class TestGetFull:
    def test_get_full_returns_body_base64url(self, proxy_module):
        body_text = "Hello, world!"
        raw = _make_simple_email(body=body_text)
        mock_conn = _mock_imap(uids=[b"101"], fetch_data=[("101", raw)])

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {"format": ["full"]}
            status, data = proxy_module.handle_get("101", qs)

        assert status == 200
        payload = data["payload"]
        assert payload["mimeType"] == "text/plain"

        # Body should be base64url encoded
        body_data = payload["body"]["data"]
        # Add padding for decoding
        padded = body_data + "=" * (-len(body_data) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        assert decoded == body_text

    def test_get_full_multipart_has_parts(self, proxy_module):
        raw = _make_multipart_email(
            text_body="Plain text version",
            html_body="<p>HTML version</p>",
        )
        mock_conn = _mock_imap(uids=[b"201"], fetch_data=[("201", raw)])

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            qs = {"format": ["full"]}
            status, data = proxy_module.handle_get("201", qs)

        assert status == 200
        payload = data["payload"]
        assert payload["mimeType"] == "multipart/alternative"
        assert "parts" in payload
        assert len(payload["parts"]) == 2

        # Check text part
        text_part = payload["parts"][0]
        assert text_part["mimeType"] == "text/plain"
        padded = text_part["body"]["data"] + "=" * (-len(text_part["body"]["data"]) % 4)
        assert base64.urlsafe_b64decode(padded).decode() == "Plain text version"

        # Check HTML part
        html_part = payload["parts"][1]
        assert html_part["mimeType"] == "text/html"
        padded = html_part["body"]["data"] + "=" * (-len(html_part["body"]["data"]) % 4)
        assert base64.urlsafe_b64decode(padded).decode() == "<p>HTML version</p>"


# ---------------------------------------------------------------------------
# Test: send message
# ---------------------------------------------------------------------------


class TestSend:
    def test_send_decodes_and_sends(self, proxy_module):
        # Build a raw message
        msg = MIMEText("unsubscribe", "plain", "utf-8")
        msg["To"] = "unsub@example.com"
        msg["Subject"] = "Unsubscribe"
        raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode()

        body = json.dumps({"raw": raw_b64}).encode()

        with patch.object(proxy_module.smtplib, "SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

            status, data = proxy_module.handle_send(body)

        assert status == 200
        assert data["id"] == "sent"
        assert "SENT" in data["labelIds"]

        # Verify SMTP was called with correct args
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("test@gmail.com", "test-password")
        mock_smtp.sendmail.assert_called_once()
        call_args = mock_smtp.sendmail.call_args
        assert call_args[0][0] == "test@gmail.com"
        assert "unsub@example.com" in call_args[0][1]

    def test_send_missing_raw_returns_400(self, proxy_module):
        body = json.dumps({}).encode()
        status, data = proxy_module.handle_send(body)
        assert status == 400
        assert "raw" in data["detail"].lower() or "Missing" in data["detail"]

    def test_send_invalid_json_returns_400(self, proxy_module):
        status, data = proxy_module.handle_send(b"not json")
        assert status == 400

    def test_send_smtp_auth_failure_returns_502(self, proxy_module):
        msg = MIMEText("unsubscribe", "plain", "utf-8")
        msg["To"] = "unsub@example.com"
        msg["Subject"] = "Unsubscribe"
        raw_b64 = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        body = json.dumps({"raw": raw_b64}).encode()

        with patch.object(proxy_module.smtplib, "SMTP") as mock_smtp_cls:
            mock_smtp = MagicMock()
            mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
            mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_smtp.login.side_effect = proxy_module.smtplib.SMTPAuthenticationError(
                535, b"Authentication failed"
            )

            status, data = proxy_module.handle_send(body)

        assert status == 502
        assert data["error"] == "auth_failed"


# ---------------------------------------------------------------------------
# Test: IMAP reconnect
# ---------------------------------------------------------------------------


class TestIMAPReconnect:
    def test_reconnects_on_stale_connection(self, proxy_module):
        # First connection goes stale
        stale_conn = MagicMock()
        stale_conn.noop.side_effect = Exception("Connection reset")

        fresh_conn = _mock_imap(uids=[b"1"])

        call_count = 0
        original_imap4ssl = proxy_module.imaplib.IMAP4_SSL

        def mock_imap4ssl(*args, **kwargs):
            return fresh_conn

        with patch.object(proxy_module.imaplib, "IMAP4_SSL", side_effect=mock_imap4ssl):
            proxy_module._imap_conn = stale_conn
            conn = proxy_module._get_imap()

        assert conn is fresh_conn
        fresh_conn.login.assert_called_once()


# ---------------------------------------------------------------------------
# Test: error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_imap_connection_failure_returns_502(self, proxy_module):
        with patch.object(proxy_module, "_get_imap", side_effect=Exception("Connection refused")):
            status, data = proxy_module.handle_list({"q": [""], "labelIds": ["INBOX"]})

        assert status == 502

    def test_get_nonexistent_message_returns_404(self, proxy_module):
        mock_conn = _mock_imap(uids=[], fetch_data=[])
        # Override uid handler to return None for FETCH
        def uid_handler(command, *args):
            if command == "FETCH":
                return ("OK", [None])
            return ("OK", [b""])
        mock_conn.uid.side_effect = uid_handler

        with patch.object(proxy_module, "_get_imap", return_value=mock_conn):
            status, data = proxy_module.handle_get("99999", {"format": ["full"]})

        assert status == 404

    def test_imap_auth_failure_returns_502(self, proxy_module):
        with patch.object(
            proxy_module.imaplib, "IMAP4_SSL"
        ) as mock_cls:
            mock_instance = MagicMock()
            mock_cls.return_value = mock_instance
            mock_instance.login.side_effect = proxy_module.imaplib.IMAP4.error(
                "LOGIN failed"
            )
            proxy_module._imap_conn = None

            status, data = proxy_module.handle_list({"q": [""], "labelIds": ["INBOX"]})

        assert status == 502


# ---------------------------------------------------------------------------
# Test: missing credentials
# ---------------------------------------------------------------------------


class TestCredentials:
    def test_main_exits_without_credentials(self, proxy_module, monkeypatch):
        monkeypatch.setattr(proxy_module, "GMAIL_ADDRESS", "")
        monkeypatch.setattr(proxy_module, "GMAIL_APP_PASSWORD", "")

        with pytest.raises(SystemExit) as exc_info:
            proxy_module.main()
        assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Test: query parsing
# ---------------------------------------------------------------------------


class TestQueryParsing:
    def test_parse_q_after_before(self, proxy_module):
        since, before = proxy_module._parse_q("after:2026/03/01 before:2026/03/08")
        assert since == "01-Mar-2026"
        assert before == "08-Mar-2026"

    def test_parse_q_only_after(self, proxy_module):
        since, before = proxy_module._parse_q("after:2026/01/15")
        assert since == "15-Jan-2026"
        assert before is None

    def test_parse_q_empty(self, proxy_module):
        since, before = proxy_module._parse_q("")
        assert since is None
        assert before is None
