"""Tests for personal_agent.email.tools MCP server."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from personal_agent.email.provider import EmailSummary, SearchResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_email(
    sender: str,
    subject: str = "Test",
    msg_id: str = "msg-1",
    has_unsub: bool = False,
    list_unsub: str = "",
    dt: datetime | None = None,
) -> EmailSummary:
    return EmailSummary(
        message_id=msg_id,
        sender=sender,
        subject=subject,
        date=dt or datetime(2026, 3, 5, 12, 0, tzinfo=timezone.utc),
        has_list_unsubscribe=has_unsub,
        list_unsubscribe=list_unsub,
    )


def _make_search_result(emails: list[EmailSummary], total: int | None = None) -> SearchResult:
    return SearchResult(emails=emails, total=total if total is not None else len(emails))


def _mock_single_provider(mock_provider):
    return patch(
        "personal_agent.email.tools._get_providers",
        return_value=[("fastmail", mock_provider)],
    )


def _mock_multi_providers(mock_fastmail, mock_gmail):
    return patch(
        "personal_agent.email.tools._get_providers",
        return_value=[("fastmail", mock_fastmail), ("gmail", mock_gmail)],
    )


# ---------------------------------------------------------------------------
# email_accounts tests
# ---------------------------------------------------------------------------


class TestEmailAccounts:
    async def test_returns_single_account(self):
        from personal_agent.email.tools import email_accounts

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = json.loads(await email_accounts())
        assert result == ["fastmail"]

    async def test_returns_multiple_accounts(self):
        from personal_agent.email.tools import email_accounts

        mock_fm = AsyncMock()
        mock_gm = AsyncMock()
        with _mock_multi_providers(mock_fm, mock_gm):
            result = json.loads(await email_accounts())
        assert result == ["fastmail", "gmail"]


# ---------------------------------------------------------------------------
# email_search tests
# ---------------------------------------------------------------------------


class TestEmailSearch:
    async def test_search_single_account(self):
        from personal_agent.email.tools import email_search

        emails = [
            _make_email("a@example.com", "Subject A", "m1"),
            _make_email("b@example.com", "Subject B", "m2"),
        ]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result(emails))

        with _mock_single_provider(mock_provider):
            raw = await email_search("2026-03-01", account="fastmail")

        result = json.loads(raw)
        assert result["total"] == 2
        assert len(result["emails"]) == 2
        assert result["emails"][0]["account"] == "fastmail"
        assert result["emails"][0]["sender"] == "a@example.com"

    async def test_search_all_accounts_merges_by_date(self):
        from personal_agent.email.tools import email_search

        fm_emails = [_make_email("fm@x.com", "FM", "fm1", dt=datetime(2026, 3, 5, 12, 0, tzinfo=timezone.utc))]
        gm_emails = [_make_email("gm@x.com", "GM", "gm1", dt=datetime(2026, 3, 6, 12, 0, tzinfo=timezone.utc))]

        mock_fm = AsyncMock()
        mock_fm.search = AsyncMock(return_value=_make_search_result(fm_emails))
        mock_gm = AsyncMock()
        mock_gm.search = AsyncMock(return_value=_make_search_result(gm_emails))

        with _mock_multi_providers(mock_fm, mock_gm):
            raw = await email_search("2026-03-01")

        result = json.loads(raw)
        assert result["total"] == 2
        # Sorted by date descending — gmail email (Mar 6) comes first
        assert result["emails"][0]["account"] == "gmail"
        assert result["emails"][1]["account"] == "fastmail"

    async def test_search_unknown_account_returns_error(self):
        from personal_agent.email.tools import email_search

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = await email_search("2026-03-01", account="nonexistent")

        assert "error" in result.lower()
        assert "nonexistent" in result.lower()

    async def test_search_respects_limit(self):
        from personal_agent.email.tools import email_search

        emails = [_make_email(f"s{i}@x.com", f"S{i}", f"m{i}") for i in range(5)]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result(emails, total=5))

        with _mock_single_provider(mock_provider):
            await email_search("2026-03-01", account="fastmail", limit=2)

        mock_provider.search.assert_called_once()
        call_kwargs = mock_provider.search.call_args
        # Check limit was passed through (could be positional or keyword)
        assert call_kwargs.kwargs.get("limit") == 2 or (len(call_kwargs.args) > 3 and call_kwargs.args[3] == 2)

    async def test_search_clamps_limit_to_50(self):
        from personal_agent.email.tools import email_search

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result([]))

        with _mock_single_provider(mock_provider):
            await email_search("2026-03-01", account="fastmail", limit=100)

        call_kwargs = mock_provider.search.call_args
        passed_limit = call_kwargs.kwargs.get("limit")
        assert passed_limit == 50

    async def test_search_no_results(self):
        from personal_agent.email.tools import email_search

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=_make_search_result([]))

        with _mock_single_provider(mock_provider):
            raw = await email_search("2026-03-01", account="fastmail")

        result = json.loads(raw)
        assert result["total"] == 0
        assert result["emails"] == []


# ---------------------------------------------------------------------------
# email_get_headers tests
# ---------------------------------------------------------------------------


class TestEmailGetHeaders:
    async def test_returns_headers_json(self):
        from personal_agent.email.tools import email_get_headers

        mock_provider = AsyncMock()
        mock_provider.get_headers = AsyncMock(return_value={
            "From": "alice@example.com",
            "Subject": "Newsletter",
            "List-Unsubscribe": "<mailto:unsub@example.com>",
        })

        with _mock_single_provider(mock_provider):
            raw = await email_get_headers("fastmail", "msg-1")

        result = json.loads(raw)
        assert result["From"] == "alice@example.com"
        assert result["List-Unsubscribe"] == "<mailto:unsub@example.com>"

    async def test_unknown_account_returns_error(self):
        from personal_agent.email.tools import email_get_headers

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = await email_get_headers("nonexistent", "msg-1")

        assert "error" in result.lower()

    async def test_routes_to_correct_provider(self):
        from personal_agent.email.tools import email_get_headers

        mock_fm = AsyncMock()
        mock_fm.get_headers = AsyncMock(return_value={"From": "fm@x.com"})
        mock_gm = AsyncMock()
        mock_gm.get_headers = AsyncMock(return_value={"From": "gm@x.com"})

        with _mock_multi_providers(mock_fm, mock_gm):
            raw = await email_get_headers("gmail", "msg-1")

        result = json.loads(raw)
        assert result["From"] == "gm@x.com"
        mock_gm.get_headers.assert_called_once_with("msg-1")
        mock_fm.get_headers.assert_not_called()


# ---------------------------------------------------------------------------
# email_get_body tests
# ---------------------------------------------------------------------------


class TestEmailGetBody:
    async def test_returns_body_string(self):
        from personal_agent.email.tools import email_get_body

        mock_provider = AsyncMock()
        mock_provider.get_body = AsyncMock(return_value="<p>Hello world</p>")

        with _mock_single_provider(mock_provider):
            result = await email_get_body("fastmail", "msg-1")

        assert result == "<p>Hello world</p>"

    async def test_unknown_account_returns_error(self):
        from personal_agent.email.tools import email_get_body

        mock_provider = AsyncMock()
        with _mock_single_provider(mock_provider):
            result = await email_get_body("nonexistent", "msg-1")

        assert "error" in result.lower()

    async def test_routes_to_correct_provider(self):
        from personal_agent.email.tools import email_get_body

        mock_fm = AsyncMock()
        mock_fm.get_body = AsyncMock(return_value="FM body")
        mock_gm = AsyncMock()
        mock_gm.get_body = AsyncMock(return_value="GM body")

        with _mock_multi_providers(mock_fm, mock_gm):
            result = await email_get_body("gmail", "msg-1")

        assert result == "GM body"
        mock_gm.get_body.assert_called_once_with("msg-1")
        mock_fm.get_body.assert_not_called()


# ---------------------------------------------------------------------------
# _get_providers() tests (unchanged behavior)
# ---------------------------------------------------------------------------


class TestGetProviders:
    def test_no_providers_raises(self):
        from personal_agent.email.tools import _get_providers

        with patch.dict("os.environ", {"FASTMAIL_API_BASE": "", "GMAIL_API_BASE": ""}, clear=False):
            with pytest.raises(RuntimeError, match="No email providers configured"):
                _get_providers()

    def test_fastmail_only(self):
        from personal_agent.email.tools import _get_providers

        with patch.dict(
            "os.environ",
            {"FASTMAIL_API_BASE": "http://proxy/fastmail", "GMAIL_API_BASE": ""},
            clear=False,
        ):
            providers = _get_providers()
            assert len(providers) == 1
            assert providers[0][0] == "fastmail"

    def test_both_providers(self):
        from personal_agent.email.tools import _get_providers

        with patch.dict(
            "os.environ",
            {
                "FASTMAIL_API_BASE": "http://proxy/fastmail",
                "GMAIL_API_BASE": "http://proxy/gmail",
            },
            clear=False,
        ):
            providers = _get_providers()
            assert len(providers) == 2
