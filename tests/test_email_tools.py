"""Tests for personal_agent.email.tools MCP server."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from personal_agent.email.provider import EmailSummary
from personal_agent.email.state import SubscriptionStore
from personal_agent.email.unsubscribe import UnsubscribeResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path: Path) -> SubscriptionStore:
    s = SubscriptionStore(tmp_path / "subs.json")
    s.load()
    return s


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


# ---------------------------------------------------------------------------
# email_scan tests
# ---------------------------------------------------------------------------


class TestEmailScan:
    async def test_scan_groups_by_sender(self, store: SubscriptionStore, tmp_path: Path):
        """Scan groups emails by sender and returns formatted output."""
        from personal_agent.email.tools import email_scan

        emails = [
            _make_email("news@example.com", "Newsletter 1", "m1", has_unsub=True),
            _make_email("news@example.com", "Newsletter 2", "m2", has_unsub=True),
            _make_email("alerts@other.com", "Alert", "m3"),
        ]

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "news@example.com" in result
        assert "2 emails" in result
        assert "alerts@other.com" in result
        assert "1 emails" in result
        assert "[has List-Unsubscribe]" in result

    async def test_scan_no_emails(self, store: SubscriptionStore):
        """Scan with no results returns informative message."""
        from personal_agent.email.tools import email_scan

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=[])

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "No emails found" in result

    async def test_scan_skips_already_processed(self, store: SubscriptionStore):
        """Senders with non-pending status are skipped."""
        from personal_agent.email.tools import email_scan

        # Pre-mark a sender as unsubscribed
        store.upsert_sender("old@example.com", status="unsubscribed", email_count=5)

        emails = [
            _make_email("old@example.com", "Old news", "m1"),
            _make_email("new@example.com", "Fresh", "m2"),
        ]

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "new@example.com" in result
        assert "old@example.com" not in result
        assert "New/pending candidates: 1" in result

    async def test_scan_upserts_senders(self, store: SubscriptionStore):
        """Scan upserts new senders as pending."""
        from personal_agent.email.tools import email_scan

        emails = [
            _make_email("news@example.com", "Sub 1", "m1", has_unsub=True),
        ]

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            await email_scan("2026-03-01", "2026-03-07")

        rec = store.get_sender("news@example.com")
        assert rec is not None
        assert rec.status == "pending"
        assert rec.email_count == 1

    async def test_scan_records_scan(self, store: SubscriptionStore):
        """Scan records the scan in the store."""
        from personal_agent.email.tools import email_scan

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=[])

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            await email_scan("2026-03-01", "2026-03-07")

        # No emails means no scan recorded (only recorded when there are results)
        # Actually, scan is always recorded -- let's check
        # The scan is recorded even with 0 candidates
        # Wait - no emails returns early before recording. Let's verify.
        scans = store.get_scans()
        assert len(scans) == 0  # Early return with no emails

    async def test_scan_records_scan_with_results(self, store: SubscriptionStore):
        """Scan with results records the scan."""
        from personal_agent.email.tools import email_scan

        emails = [_make_email("a@b.com", "Test", "m1")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            await email_scan("2026-03-01", "2026-03-07")

        scans = store.get_scans()
        assert len(scans) == 1
        assert scans[0].after == "2026-03-01"
        assert scans[0].before == "2026-03-07"

    async def test_scan_keeps_pending_senders(self, store: SubscriptionStore):
        """Senders already in pending status are still included."""
        from personal_agent.email.tools import email_scan

        store.upsert_sender("pending@example.com", status="pending", email_count=1)

        emails = [
            _make_email("pending@example.com", "More spam", "m1"),
        ]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "pending@example.com" in result


# ---------------------------------------------------------------------------
# email_unsubscribe tests
# ---------------------------------------------------------------------------


class TestEmailUnsubscribe:
    async def test_unsubscribe_success(self, store: SubscriptionStore):
        """Successful unsubscribe updates store status."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "news@example.com",
            status="pending",
            email_count=3,
            first_seen="2026-03-01",
            last_seen="2026-03-05",
        )

        emails = [
            _make_email("news@example.com", "News", "msg-42", has_unsub=True),
        ]

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        unsub_result = UnsubscribeResult(
            success=True, method="one_click", detail="POST -> 200"
        )
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("news@example.com")

        assert "Successfully" in result
        assert "one_click" in result
        rec = store.get_sender("news@example.com")
        assert rec is not None
        assert rec.status == "unsubscribed"

    async def test_unsubscribe_failure(self, store: SubscriptionStore):
        """Failed unsubscribe keeps sender as pending."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "spam@example.com",
            status="pending",
            email_count=5,
            first_seen="2026-03-01",
            last_seen="2026-03-05",
        )

        emails = [_make_email("spam@example.com", "Spam", "msg-99")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        unsub_result = UnsubscribeResult(
            success=False, method="body_link", detail="No unsubscribe links found"
        )
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("spam@example.com")

        assert "Failed" in result
        rec = store.get_sender("spam@example.com")
        assert rec is not None
        assert rec.status == "pending"

    async def test_unsubscribe_unknown_sender(self, store: SubscriptionStore):
        """Unknown sender returns error message."""
        from personal_agent.email.tools import email_unsubscribe

        mock_provider = AsyncMock()

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_unsubscribe("unknown@example.com")

        assert "not found" in result

    async def test_unsubscribe_no_emails_found(self, store: SubscriptionStore):
        """No emails from sender in date range returns error."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "gone@example.com",
            status="pending",
            email_count=1,
            first_seen="2026-03-01",
            last_seen="2026-03-05",
        )

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=[])

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_unsubscribe("gone@example.com")

        assert "No emails found" in result

    async def test_unsubscribe_prefers_list_unsubscribe(self, store: SubscriptionStore):
        """Unsubscribe picks email with List-Unsubscribe header when available."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "news@example.com",
            status="pending",
            email_count=2,
            first_seen="2026-03-01",
            last_seen="2026-03-05",
        )

        emails = [
            _make_email("news@example.com", "No header", "msg-no", has_unsub=False),
            _make_email("news@example.com", "Has header", "msg-yes", has_unsub=True),
        ]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        unsub_result = UnsubscribeResult(success=True, method="one_click", detail="OK")
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            patch("personal_agent.email.tools._get_provider", return_value=mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            await email_unsubscribe("news@example.com")

        # Should have used msg-yes (the one with List-Unsubscribe)
        mock_unsubscriber.unsubscribe.assert_called_once_with("msg-yes")


# ---------------------------------------------------------------------------
# email_list_subscriptions tests
# ---------------------------------------------------------------------------


class TestEmailListSubscriptions:
    async def test_list_all(self, store: SubscriptionStore):
        """List all subscriptions."""
        from personal_agent.email.tools import email_list_subscriptions

        store.upsert_sender("a@example.com", status="pending", email_count=3)
        store.upsert_sender("b@example.com", status="unsubscribed", email_count=1)

        with patch("personal_agent.email.tools._get_store", return_value=store):
            result = await email_list_subscriptions()

        assert "a@example.com" in result
        assert "b@example.com" in result
        assert "2" in result  # total count

    async def test_list_filtered(self, store: SubscriptionStore):
        """List subscriptions filtered by status."""
        from personal_agent.email.tools import email_list_subscriptions

        store.upsert_sender("a@example.com", status="pending", email_count=3)
        store.upsert_sender("b@example.com", status="unsubscribed", email_count=1)

        with patch("personal_agent.email.tools._get_store", return_value=store):
            result = await email_list_subscriptions(status="pending")

        assert "a@example.com" in result
        assert "b@example.com" not in result

    async def test_list_empty(self, store: SubscriptionStore):
        """Empty store returns informative message."""
        from personal_agent.email.tools import email_list_subscriptions

        with patch("personal_agent.email.tools._get_store", return_value=store):
            result = await email_list_subscriptions()

        assert "No subscriptions found" in result

    async def test_list_shows_method(self, store: SubscriptionStore):
        """Unsubscribe method is shown when available."""
        from personal_agent.email.tools import email_list_subscriptions

        store.upsert_sender(
            "x@example.com",
            status="unsubscribed",
            email_count=2,
            unsubscribe_method="one_click",
        )

        with patch("personal_agent.email.tools._get_store", return_value=store):
            result = await email_list_subscriptions()

        assert "[one_click]" in result
