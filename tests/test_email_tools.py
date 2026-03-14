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
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            await email_scan("2026-03-01", "2026-03-07")

        scans = store.get_scans()
        assert len(scans) == 0  # Early return with no emails

    async def test_scan_records_scan_with_results(self, store: SubscriptionStore):
        """Scan with results records the scan."""
        from personal_agent.email.tools import email_scan

        emails = [_make_email("a@b.com", "Test", "m1")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "pending@example.com" in result

    async def test_scan_keeps_attempted_senders(self, store: SubscriptionStore):
        """Senders with 'attempted' status are still included (need manual follow-up)."""
        from personal_agent.email.tools import email_scan

        store.upsert_sender(
            "attempted@example.com", status="attempted", email_count=1,
            unsubscribe_method="body_link",
        )

        emails = [
            _make_email("attempted@example.com", "Still coming", "m1"),
        ]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "attempted@example.com" in result


# ---------------------------------------------------------------------------
# Multi-provider email_scan tests
# ---------------------------------------------------------------------------


class TestEmailScanMultiProvider:
    async def test_scan_merges_results_from_both_providers(self, store: SubscriptionStore):
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

        with (
            _mock_multi_providers(mock_fastmail, mock_gmail),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "fm-news@example.com" in result
        assert "gm-news@example.com" in result
        assert "Total emails: 2" in result

    async def test_scan_tracks_provider_per_sender(self, store: SubscriptionStore):
        """Subscription store records which provider each sender came from."""
        from personal_agent.email.tools import email_scan

        fastmail_emails = [
            _make_email("fm@example.com", "FM", "fm-1"),
        ]
        gmail_emails = [
            _make_email("gm@example.com", "GM", "gm-1"),
        ]

        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=fastmail_emails)
        mock_gmail = AsyncMock()
        mock_gmail.search = AsyncMock(return_value=gmail_emails)

        with (
            _mock_multi_providers(mock_fastmail, mock_gmail),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            await email_scan("2026-03-01", "2026-03-07")

        fm_rec = store.get_sender("fm@example.com")
        assert fm_rec is not None
        assert fm_rec.provider == "fastmail"

        gm_rec = store.get_sender("gm@example.com")
        assert gm_rec is not None
        assert gm_rec.provider == "gmail"

    async def test_scan_shows_provider_label_with_multi(self, store: SubscriptionStore):
        """When multiple providers are active, output includes provider labels."""
        from personal_agent.email.tools import email_scan

        fastmail_emails = [_make_email("fm@example.com", "FM", "fm-1")]
        gmail_emails = [_make_email("gm@example.com", "GM", "gm-1")]

        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=fastmail_emails)
        mock_gmail = AsyncMock()
        mock_gmail.search = AsyncMock(return_value=gmail_emails)

        with (
            _mock_multi_providers(mock_fastmail, mock_gmail),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "(fastmail)" in result
        assert "(gmail)" in result

    async def test_scan_works_with_only_fastmail(self, store: SubscriptionStore):
        """Backward compat: works with only Fastmail configured."""
        from personal_agent.email.tools import email_scan

        emails = [_make_email("sender@example.com", "Test", "m1")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "sender@example.com" in result
        # No provider label with single provider
        assert "(fastmail)" not in result

    async def test_scan_works_with_only_gmail(self, store: SubscriptionStore):
        """Works with only Gmail configured."""
        from personal_agent.email.tools import email_scan

        emails = [_make_email("sender@example.com", "Test", "m1")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        with (
            patch(
                "personal_agent.email.tools._get_providers",
                return_value=[("gmail", mock_provider)],
            ),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "sender@example.com" in result

    async def test_scan_no_emails_from_any_provider(self, store: SubscriptionStore):
        """No emails from any provider returns informative message."""
        from personal_agent.email.tools import email_scan

        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=[])
        mock_gmail = AsyncMock()
        mock_gmail.search = AsyncMock(return_value=[])

        with (
            _mock_multi_providers(mock_fastmail, mock_gmail),
            patch("personal_agent.email.tools._get_store", return_value=store),
        ):
            result = await email_scan("2026-03-01", "2026-03-07")

        assert "No emails found" in result


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
            provider="fastmail",
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
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("spam@example.com")

        assert "Failed" in result
        rec = store.get_sender("spam@example.com")
        assert rec is not None
        assert rec.status == "pending"

    async def test_unsubscribe_unreliable_method_marks_attempted(self, store: SubscriptionStore):
        """Unsubscribe via https or body_link marks as 'attempted', not 'unsubscribed'."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "news@example.com",
            status="pending",
            email_count=2,
            first_seen="2026-03-01",
            last_seen="2026-03-05",
            provider="fastmail",
        )

        emails = [
            _make_email("news@example.com", "News", "msg-50", has_unsub=False),
        ]

        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        # https method returns success=True but is not a confirmed method
        unsub_result = UnsubscribeResult(
            success=True, method="https", detail="POST https://example.com/unsub -> 200"
        )
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("news@example.com")

        assert "Attempted" in result
        assert "cannot confirm" in result
        rec = store.get_sender("news@example.com")
        assert rec is not None
        assert rec.status == "attempted"
        assert rec.unsubscribe_method == "https"

    async def test_unsubscribe_body_link_marks_attempted(self, store: SubscriptionStore):
        """Unsubscribe via body_link also marks as 'attempted'."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "promo@example.com",
            status="pending",
            email_count=1,
            first_seen="2026-03-01",
            last_seen="2026-03-01",
            provider="fastmail",
        )

        emails = [_make_email("promo@example.com", "Promo", "msg-60")]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        unsub_result = UnsubscribeResult(
            success=True, method="body_link", detail="GET https://example.com/unsub -> 200"
        )
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("promo@example.com")

        assert "Attempted" in result
        assert "cannot confirm" in result
        rec = store.get_sender("promo@example.com")
        assert rec is not None
        assert rec.status == "attempted"

    async def test_unsubscribe_mailto_marks_unsubscribed(self, store: SubscriptionStore):
        """Unsubscribe via mailto is a confirmed method."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "list@example.com",
            status="pending",
            email_count=1,
            first_seen="2026-03-01",
            last_seen="2026-03-01",
            provider="fastmail",
        )

        emails = [_make_email("list@example.com", "List", "msg-70", has_unsub=True)]
        mock_provider = AsyncMock()
        mock_provider.search = AsyncMock(return_value=emails)

        unsub_result = UnsubscribeResult(
            success=True, method="mailto", detail="Sent unsubscribe email to unsub@example.com"
        )
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("list@example.com")

        assert "Successfully" in result
        rec = store.get_sender("list@example.com")
        assert rec is not None
        assert rec.status == "unsubscribed"

    async def test_unsubscribe_unknown_sender(self, store: SubscriptionStore):
        """Unknown sender returns error message."""
        from personal_agent.email.tools import email_unsubscribe

        mock_provider = AsyncMock()

        with (
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
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
            _mock_single_provider(mock_provider),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            await email_unsubscribe("news@example.com")

        # Should have used msg-yes (the one with List-Unsubscribe)
        mock_unsubscriber.unsubscribe.assert_called_once_with("msg-yes")


# ---------------------------------------------------------------------------
# Multi-provider email_unsubscribe tests
# ---------------------------------------------------------------------------


class TestEmailUnsubscribeMultiProvider:
    async def test_unsubscribe_routes_to_correct_provider(self, store: SubscriptionStore):
        """Unsubscribe uses the provider that originally found the sender."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "gmail-sender@example.com",
            status="pending",
            email_count=3,
            first_seen="2026-03-01",
            last_seen="2026-03-05",
            provider="gmail",
        )

        emails = [
            _make_email("gmail-sender@example.com", "News", "gm-42", has_unsub=True),
        ]

        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=[])
        mock_gmail = AsyncMock()
        mock_gmail.search = AsyncMock(return_value=emails)

        unsub_result = UnsubscribeResult(
            success=True, method="one_click", detail="POST -> 200"
        )
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            _mock_multi_providers(mock_fastmail, mock_gmail),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("gmail-sender@example.com")

        assert "Successfully" in result
        # Gmail provider should have been called, not fastmail
        mock_gmail.search.assert_called_once()
        mock_fastmail.search.assert_not_called()

    async def test_unsubscribe_falls_back_to_first_provider(self, store: SubscriptionStore):
        """If no provider is stored, falls back to first provider."""
        from personal_agent.email.tools import email_unsubscribe

        store.upsert_sender(
            "old-sender@example.com",
            status="pending",
            email_count=1,
            first_seen="2026-03-01",
            last_seen="2026-03-05",
            # No provider field
        )

        emails = [
            _make_email("old-sender@example.com", "Old", "fm-1"),
        ]
        mock_fastmail = AsyncMock()
        mock_fastmail.search = AsyncMock(return_value=emails)
        mock_gmail = AsyncMock()

        unsub_result = UnsubscribeResult(
            success=False, method="body_link", detail="No links"
        )
        mock_unsubscriber = AsyncMock()
        mock_unsubscriber.unsubscribe = AsyncMock(return_value=unsub_result)

        with (
            _mock_multi_providers(mock_fastmail, mock_gmail),
            patch("personal_agent.email.tools._get_store", return_value=store),
            patch("personal_agent.email.tools.Unsubscriber", return_value=mock_unsubscriber),
        ):
            result = await email_unsubscribe("old-sender@example.com")

        # First provider (fastmail) should have been used
        mock_fastmail.search.assert_called_once()


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


# ---------------------------------------------------------------------------
# _get_providers() tests
# ---------------------------------------------------------------------------


class TestGetProviders:
    def test_no_providers_raises(self):
        from personal_agent.email.tools import _get_providers

        with (
            patch.dict("os.environ", {"FASTMAIL_API_BASE": "", "GMAIL_API_BASE": ""}, clear=False),
        ):
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
