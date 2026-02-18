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
async def test_sends_anthropic_api_key(monkeypatch, httpx_mock):
    """x-api-key and anthropic-version headers must be present."""
    monkeypatch.setattr(action_review, "ANTHROPIC_API_KEY", "test-anthropic-key-456")
    httpx_mock.add_response(
        url="http://api.anthropic.com/v1/messages",
        json={
            "content": [{"type": "text", "text": ALIGNED_RESPONSE}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 50, "output_tokens": 20},
        },
    )
    await review_action(
        user_intent="Send email to alice@example.com",
        tool_name="send_email",
        tool_args={"to": "alice@example.com", "subject": "Hi", "body": "..."},
    )
    request = httpx_mock.get_requests()[0]
    assert request.headers["x-api-key"] == "test-anthropic-key-456"
    assert request.headers["anthropic-version"] == "2023-06-01"


@pytest.mark.asyncio
async def test_sends_correct_model_and_prompt(httpx_mock, monkeypatch):
    """Request body must contain the review model and a prompt with user intent."""
    import json
    monkeypatch.setattr(action_review, "ANTHROPIC_API_KEY", "test-key")
    httpx_mock.add_response(
        url="http://api.anthropic.com/v1/messages",
        json={
            "content": [{"type": "text", "text": ALIGNED_RESPONSE}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 50, "output_tokens": 20},
        },
    )
    await review_action(
        user_intent="Buy groceries for under $50",
        tool_name="make_purchase",
        tool_args={"item": "groceries", "amount": 45.00},
    )
    request = httpx_mock.get_requests()[0]
    body = json.loads(request.content)
    assert body["model"] == "claude-haiku-4-5-20241022"
    assert "Buy groceries for under $50" in body["messages"][0]["content"]
    assert "make_purchase" in body["messages"][0]["content"]


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
