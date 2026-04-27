"""Tests for the auto-continue wrapper around nanobot's max_tool_iterations.

When nanobot's AgentLoop hits max_tool_iterations, it emits a final outbound
message starting with "I reached the maximum number of tool call iterations".
We detect that sentinel and re-inject a synthetic inbound 'continue' message,
capped per-session to prevent runaway loops.
"""

import pytest

from nanobot.bus.queue import MessageBus
from nanobot.bus.events import OutboundMessage

from personal_agent.main import (
    _AUTO_CONTINUE_PROMPT,
    _AUTO_CONTINUE_SENTINEL,
    _maybe_auto_continue,
)


def _outbound(content: str, *, progress: bool = False) -> OutboundMessage:
    metadata = {"_progress": True} if progress else {}
    return OutboundMessage(
        channel="zulip",
        chat_id="test:topic",
        content=content,
        metadata=metadata,
    )


async def test_sentinel_reinjects_continue_message():
    bus = MessageBus()
    counts: dict[str, int] = {}

    await _maybe_auto_continue(bus, _outbound(_AUTO_CONTINUE_SENTINEL + " (40)..."), counts)

    assert bus.inbound_size == 1
    msg = await bus.consume_inbound()
    assert msg.channel == "zulip"
    assert msg.chat_id == "test:topic"
    assert msg.content == _AUTO_CONTINUE_PROMPT
    assert msg.sender_id == "__auto_continue__"
    assert counts["zulip:test:topic"] == 1


async def test_normal_reply_resets_counter():
    bus = MessageBus()
    counts = {"zulip:test:topic": 2}

    await _maybe_auto_continue(bus, _outbound("Here's the answer you asked for."), counts)

    assert bus.inbound_size == 0
    assert "zulip:test:topic" not in counts


async def test_progress_message_is_ignored():
    bus = MessageBus()
    counts = {"zulip:test:topic": 1}

    # A progress frame happens to mention the sentinel — must NOT trigger.
    await _maybe_auto_continue(
        bus,
        _outbound(_AUTO_CONTINUE_SENTINEL, progress=True),
        counts,
    )

    assert bus.inbound_size == 0
    assert counts["zulip:test:topic"] == 1  # untouched


async def test_caps_at_max_retries():
    bus = MessageBus()
    counts: dict[str, int] = {}

    for _ in range(5):
        await _maybe_auto_continue(
            bus,
            _outbound(_AUTO_CONTINUE_SENTINEL),
            counts,
            max_retries=3,
        )

    # Three injections, then nothing — and the counter stays sticky-exhausted
    # so a later stray sentinel can't re-arm the loop.
    assert bus.inbound_size == 3
    assert counts["zulip:test:topic"] == 3

    # A successful reply must clear the exhausted state.
    await _maybe_auto_continue(bus, _outbound("done."), counts)
    assert "zulip:test:topic" not in counts


async def test_independent_sessions_have_independent_counters():
    bus = MessageBus()
    counts: dict[str, int] = {}

    msg_a = OutboundMessage(channel="zulip", chat_id="streamA:t", content=_AUTO_CONTINUE_SENTINEL)
    msg_b = OutboundMessage(channel="zulip", chat_id="streamB:t", content=_AUTO_CONTINUE_SENTINEL)

    for _ in range(3):
        await _maybe_auto_continue(bus, msg_a, counts, max_retries=3)
    # Session A is exhausted; session B should still get its first retry.
    await _maybe_auto_continue(bus, msg_b, counts, max_retries=3)

    assert bus.inbound_size == 4  # 3 from A, 1 from B
    assert counts.get("zulip:streamB:t") == 1


@pytest.mark.parametrize("content", [
    "I reached the maximum number of tool call iterations (40) without completing the task.",
    "I reached the maximum number of tool call iterations (100) without completing.",
])
async def test_matches_real_nanobot_message(content):
    bus = MessageBus()
    counts: dict[str, int] = {}

    await _maybe_auto_continue(bus, _outbound(content), counts)

    assert bus.inbound_size == 1
