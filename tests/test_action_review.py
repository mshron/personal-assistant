import pytest

from personal_agent.guardrails import action_review
from personal_agent.guardrails.action_review import review_action, ReviewResult


@pytest.fixture(autouse=True)
def _reset_client():
    """Reset module-level httpx client between tests."""
    action_review._client = None
    yield
    action_review._client = None


ALIGNED_RESPONSE = '{"aligned": true, "reason": "Action matches user intent."}'
MISALIGNED_RESPONSE = '{"aligned": false, "reason": "User asked to email Alice but action sends to Bob."}'


@pytest.fixture
def mock_haiku_aligned(httpx_mock):
    httpx_mock.add_response(
        url="http://api.anthropic.com/v1/messages",
        json={
            "content": [{"type": "text", "text": ALIGNED_RESPONSE}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 50, "output_tokens": 20},
        },
    )


@pytest.fixture
def mock_haiku_misaligned(httpx_mock):
    httpx_mock.add_response(
        url="http://api.anthropic.com/v1/messages",
        json={
            "content": [{"type": "text", "text": MISALIGNED_RESPONSE}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 50, "output_tokens": 20},
        },
    )


@pytest.mark.asyncio
async def test_aligned_action_approved(mock_haiku_aligned):
    result = await review_action(
        user_intent="Send an email to alice@example.com about the meeting",
        tool_name="send_email",
        tool_args={"to": "alice@example.com", "subject": "Meeting", "body": "..."},
    )
    assert result.approved


@pytest.mark.asyncio
async def test_misaligned_action_blocked(mock_haiku_misaligned):
    result = await review_action(
        user_intent="Send an email to alice@example.com about the meeting",
        tool_name="send_email",
        tool_args={"to": "bob@evil.com", "subject": "Meeting", "body": "..."},
    )
    assert not result.approved


@pytest.mark.asyncio
async def test_non_side_effecting_tool_auto_approved():
    """Tools not in SIDE_EFFECTING_TOOLS are auto-approved without API call."""
    result = await review_action(
        user_intent="Search for python tutorials",
        tool_name="web_search",
        tool_args={"query": "python tutorials"},
    )
    assert result.approved
    assert result.skipped
