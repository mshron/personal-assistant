"""Tests for personal_agent.email.tools MCP server."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from personal_agent.email.provider import EmailSummary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_email(
    sender: str,
    subject: str = "Test",
    msg_id: str = "msg-1",
    has_unsub: bool = False,
    dt: datetime | None = None,
) -> EmailSummary:
    return EmailSummary(
        message_id=msg_id,
        sender=sender,
        subject=subject,
        date=dt or datetime(2026, 3, 5, 12, 0, tzinfo=timezone.utc),
        has_list_unsubscribe=has_unsub,
    )


def _mock_single_provider(mock_provider):
    """Patch _get_providers to return a single mock provider."""
    return patch(
        "personal_agent.email.tools._get_providers",
        return_value=[("fastmail", mock_provider)],
    )


def _mock_multi_providers(mock_fastmail, mock_gmail):
    """Patch _get_providers to return two mock providers."""
    return patch(
        "personal_agent.email.tools._get_providers",
        return_value=[("fastmail", mock_fastmail), ("gmail", mock_gmail)],
    )


# ---------------------------------------------------------------------------
# email_scan tests
# ---------------------------------------------------------------------------


class TestEmailScan:
    async def test_scan_groups_by_sender(self):
        """Scan groups emails by sender and returns formatted output."""
        from personal_agent.email.tools import email_scan

        emails = [
            _make_email("news@example.com", "Newsletter 1", "m1", has_unsub=True),
            _make_email("news@example.com", "Newsletter 2", "m2", has_unsub=True),
            _make_email("alerts@other.com", "Alert", "m3"),
        ]

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with _mock_single_provider(mock_provider):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "news@example.com" in result
        assert "2 emails" in result
        assert "alerts@other.com" in result
        assert "1 emails" in result
        assert "[has List-Unsubscribe]" in result

    async def test_scan_no_emails(self):
        """Scan with no results returns informative message."""
        from personal_agent.email.tools import email_scan

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=[])

        with _mock_single_provider(mock_provider):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "No emails found" in result

    async def test_scan_returns_all_senders(self):
        """Scan returns all senders without filtering."""
        from personal_agent.email.tools import email_scan

        emails = [
            _make_email("a@example.com", "A", "m1"),
            _make_email("b@example.com", "B", "m2"),
            _make_email("c@example.com", "C", "m3"),
        ]

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with _mock_single_provider(mock_provider):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "a@example.com" in result
        assert "b@example.com" in result
        assert "c@example.com" in result
        assert "Unique senders: 3" in result


# ---------------------------------------------------------------------------
# Multi-provider email_scan tests
# ---------------------------------------------------------------------------


class TestEmailScanMultiProvider:
    async def test_scan_merges_results_from_both_providers(self):
        """email_scan merges results from Fastmail and Gmail."""
        from personal_agent.email.tools import email_scan

        fastmail_emails = [
            _make_email("fm-news@example.com", "FM Newsletter", "fm-1", has_unsub=True),
        ]
        gmail_emails = [
            _make_email("gm-news@example.com", "GM Newsletter", "gm-1", has_unsub=True),
        ]

        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=fastmail_emails)
        mock_gmail = AsyncMock()
        mock_gmail.search = AsyncMock(return_value=gmail_emails)

        with _mock_multi_providers(mock_fastmail, mock_gmail):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "fm-news@example.com" in result
        assert "gm-news@example.com" in result
        assert "Total emails: 2" in result

    async def test_scan_shows_provider_label_with_multi(self):
        """When multiple providers are active, output includes provider labels."""
        from personal_agent.email.tools import email_scan

        fastmail_emails = [_make_email("fm@example.com", "FM", "fm-1")]
        gmail_emails = [_make_email("gm@example.com", "GM", "gm-1")]

        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=fastmail_emails)
        mock_gmail = AsyncMock()
        mock_gmail.search = AsyncMock(return_value=gmail_emails)

        with _mock_multi_providers(mock_fastmail, mock_gmail):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "(fastmail)" in result
        assert "(gmail)" in result

    async def test_scan_works_with_only_fastmail(self):
        """Works with only Fastmail configured."""
        from personal_agent.email.tools import email_scan

        emails = [_make_email("sender@example.com", "Test", "m1")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with _mock_single_provider(mock_provider):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "sender@example.com" in result
        assert "(fastmail)" not in result

    async def test_scan_works_with_only_gmail(self):
        """Works with only Gmail configured."""
        from personal_agent.email.tools import email_scan

        emails = [_make_email("sender@example.com", "Test", "m1")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with patch(
            "personal_agent.email.tools._get_providers",
            return_value=[("gmail", mock_provider)],
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "sender@example.com" in result

    async def test_scan_no_emails_from_any_provider(self):
        """No emails from any provider returns informative message."""
        from personal_agent.email.tools import email_scan

        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=[])
        mock_gmail = AsyncMock()
        mock_gmail.search = AsyncMock(return_value=[])

        with _mock_multi_providers(mock_fastmail, mock_gmail):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "No emails found" in result


# ---------------------------------------------------------------------------
# _get_providers() tests
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

    def test_gmail_only(self):
        from personal_agent.email.tools import _get_providers

        with patch.dict(
            "os.environ",
            {"FASTMAIL_API_BASE": "", "GMAIL_API_BASE": "http://proxy/gmail"},
            clear=False,
        ):
            providers = _get_providers()
            assert len(providers) == 1
            assert providers[0][0] == "gmail"

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
            names = [p[0] for p in providers]
            assert "fastmail" in names
            assert "gmail" in names
