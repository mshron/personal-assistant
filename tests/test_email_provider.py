"""Tests for the email provider abstraction layer."""

from datetime import date, datetime

import pytest

from personal_agent.email.provider import EmailProvider, EmailSummary


# ---------------------------------------------------------------------------
# EmailSummary dataclass
# ---------------------------------------------------------------------------


class TestEmailSummary:
    def test_fields(self):
        ts = datetime(2026, 3, 1, 12, 0, 0)
        s = EmailSummary(
            message_id="abc123",
            sender="alice@example.com",
            subject="Weekly digest",
            date=ts,
            has_list_unsubscribe=True,
        )
        assert s.message_id == "abc123"
        assert s.sender == "alice@example.com"
        assert s.subject == "Weekly digest"
        assert s.date == ts
        assert s.has_list_unsubscribe is True

    def test_equality(self):
        ts = datetime(2026, 1, 1)
        a = EmailSummary("id1", "bob@x.com", "Hi", ts, False)
        b = EmailSummary("id1", "bob@x.com", "Hi", ts, False)
        assert a == b

    def test_defaults_not_present(self):
        """All fields are required -- no defaults."""
        with pytest.raises(TypeError):
            EmailSummary()  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Abstract base class cannot be instantiated
# ---------------------------------------------------------------------------


class TestAbstractProvider:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            EmailProvider()  # type: ignore[abstract]

    def test_partial_implementation_fails(self):
        class Partial(EmailProvider):
            async def search(self, after, before, folder="Inbox"):
                return []

        with pytest.raises(TypeError):
            Partial()


# ---------------------------------------------------------------------------
# send_simple validation
# ---------------------------------------------------------------------------


class _StubProvider(EmailProvider):
    """Minimal concrete provider for testing send_simple validation."""

    async def search(self, after, before, folder="Inbox"):
        return []

    async def get_headers(self, message_id):
        return {}

    async def get_body(self, message_id):
        return ""


class TestSendSimpleValidation:
    @pytest.fixture
    def provider(self):
        return _StubProvider()

    async def test_rejects_long_body(self, provider):
        long_body = "unsubscribe " + "x" * 50
        with pytest.raises(ValueError, match="exceeds 50 characters"):
            await provider.send_simple("a@b.com", "unsub", long_body)

    async def test_rejects_non_unsubscribe_content(self, provider):
        with pytest.raises(ValueError, match="does not appear to be unsubscribe"):
            await provider.send_simple("a@b.com", "Hello", "Just saying hi")

    async def test_accepts_unsubscribe_in_body(self, provider):
        # Should not raise
        await provider.send_simple("a@b.com", "Request", "unsubscribe")

    async def test_accepts_unsubscribe_in_subject(self, provider):
        # Should not raise when "unsub" appears in subject
        await provider.send_simple("a@b.com", "Unsubscribe request", "please")

    async def test_body_exactly_50_chars_ok(self, provider):
        body = "unsubscribe" + "x" * 39  # 50 chars total
        assert len(body) == 50
        await provider.send_simple("a@b.com", "unsub", body)

    async def test_body_51_chars_rejected(self, provider):
        body = "unsubscribe" + "x" * 40  # 51 chars
        assert len(body) == 51
        with pytest.raises(ValueError, match="exceeds 50 characters"):
            await provider.send_simple("a@b.com", "unsub", body)
