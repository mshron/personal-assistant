"""Tests for the Zulip channel."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nanobot.bus.events import OutboundMessage
from personal_agent.zulip_channel import ZulipChannel, ZulipConfig


# -- ZulipConfig tests --------------------------------------------------------


def test_config_from_env():
    env = {
        "ZULIP_SITE": "https://polynumeral.zulipchat.com",
        "ZULIP_EMAIL": "bot@polynumeral.zulipchat.com",
        "ZULIP_API_KEY": "abc123",
        "ZULIP_STREAMS": "general, testing",
        "ZULIP_ALLOW_FROM": "alice,bob",
    }
    with patch.dict("os.environ", env, clear=False):
        cfg = ZulipConfig.from_env()

    assert cfg.site == "https://polynumeral.zulipchat.com"
    assert cfg.email == "bot@polynumeral.zulipchat.com"
    assert cfg.api_key == "abc123"
    assert cfg.streams == ["general", "testing"]
    assert cfg.allow_from == ["alice", "bob"]


def test_config_missing_required():
    env = {"ZULIP_SITE": "", "ZULIP_EMAIL": "", "ZULIP_API_KEY": ""}
    with patch.dict("os.environ", env, clear=False):
        with pytest.raises(ValueError, match="ZULIP_SITE"):
            ZulipConfig.from_env()


def test_config_empty_streams():
    env = {
        "ZULIP_SITE": "https://test.zulipchat.com",
        "ZULIP_EMAIL": "bot@test.zulipchat.com",
        "ZULIP_API_KEY": "key",
        "ZULIP_STREAMS": "",
        "ZULIP_ALLOW_FROM": "",
    }
    with patch.dict("os.environ", env, clear=False):
        cfg = ZulipConfig.from_env()
    assert cfg.streams == []
    # Empty ZULIP_ALLOW_FROM defaults to ["*"] (nanobot 0.1.4.post4 compat)
    assert cfg.allow_from == ["*"]


def test_config_unset_allow_from_defaults_to_wildcard():
    """When ZULIP_ALLOW_FROM is unset, allow_from defaults to ['*']."""
    env = {
        "ZULIP_SITE": "https://test.zulipchat.com",
        "ZULIP_EMAIL": "bot@test.zulipchat.com",
        "ZULIP_API_KEY": "key",
        "ZULIP_STREAMS": "general",
    }
    with patch.dict("os.environ", env, clear=True):
        cfg = ZulipConfig.from_env()
    assert cfg.allow_from == ["*"]


def test_config_explicit_allow_from_preserved():
    """Explicit ZULIP_ALLOW_FROM values are preserved as-is."""
    env = {
        "ZULIP_SITE": "https://test.zulipchat.com",
        "ZULIP_EMAIL": "bot@test.zulipchat.com",
        "ZULIP_API_KEY": "key",
        "ZULIP_ALLOW_FROM": "42,99",
    }
    with patch.dict("os.environ", env, clear=False):
        cfg = ZulipConfig.from_env()
    assert cfg.allow_from == ["42", "99"]


# -- Helpers -------------------------------------------------------------------


def _make_config(**overrides) -> ZulipConfig:
    defaults = dict(
        site="https://test.zulipchat.com",
        email="bot@test.zulipchat.com",
        api_key="testkey",
        streams=["general"],
        allow_from=["*"],  # nanobot 0.1.4.post4: empty list denies all
    )
    defaults.update(overrides)
    return ZulipConfig(**defaults)


def _make_channel(config=None, tmp_path=None) -> ZulipChannel:
    config = config or _make_config()
    bus = MagicMock()
    bus.publish_inbound = AsyncMock()
    with patch("personal_agent.zulip_channel.zulip.Client"):
        channel = ZulipChannel(config, bus)
    # Use a temp file for engaged topics in tests
    if tmp_path is not None:
        channel._engaged_topics_file = tmp_path / "engaged_topics.json"
    return channel


def _stream_message(**overrides) -> dict:
    defaults = dict(
        type="stream",
        sender_id=42,
        sender_email="alice@test.com",
        display_recipient="general",
        subject="greetings",
        content="hello bot",
    )
    defaults.update(overrides)
    return defaults


def _dm_message(**overrides) -> dict:
    defaults = dict(
        type="private",
        sender_id=42,
        sender_email="alice@test.com",
        display_recipient=[
            {"id": 42, "email": "alice@test.com"},
            {"id": 1, "email": "bot@test.zulipchat.com"},
        ],
        content="hi there",
    )
    defaults.update(overrides)
    return defaults


async def _call_from_thread(channel, message):
    """Call _on_message_sync from a thread, matching production behavior.

    In production, Zulip's call_on_each_event runs in a daemon thread.
    run_coroutine_threadsafe + future.result() would deadlock if called
    from the event loop thread, so we must run it in a separate thread.
    """
    await asyncio.to_thread(channel._on_message_sync, message)


# -- Message handling tests ----------------------------------------------------


async def test_skip_own_messages(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # Own messages return before hitting run_coroutine_threadsafe, so no deadlock
    channel._on_message_sync(_stream_message(sender_email="bot@test.zulipchat.com"))
    channel.bus.publish_inbound.assert_not_awaited()


async def test_stream_message_with_mention_publishes(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    await _call_from_thread(
        channel, _stream_message(content="@**TestBot** hello bot")
    )

    channel.bus.publish_inbound.assert_awaited_once()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.channel == "zulip"
    assert msg.chat_id == "general:greetings"
    assert msg.content == "hello bot"
    assert msg.sender_id == "42"


async def test_stream_message_without_mention_ignored(tmp_path):
    """Messages in non-engaged topics without @mention are skipped."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # No mention, topic not engaged — should be ignored
    channel._on_message_sync(_stream_message(content="hello bot"))
    channel.bus.publish_inbound.assert_not_awaited()


async def test_engaged_topic_receives_all_messages(tmp_path):
    """Once mentioned in a topic, subsequent messages are processed."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # First: @mention engages the topic
    await _call_from_thread(
        channel, _stream_message(content="@**TestBot** hi")
    )
    channel.bus.publish_inbound.assert_awaited_once()
    channel.bus.publish_inbound.reset_mock()

    # Second: no mention, but topic is engaged — should still process
    await _call_from_thread(
        channel, _stream_message(content="follow up question")
    )
    channel.bus.publish_inbound.assert_awaited_once()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.content == "follow up question"


async def test_different_topic_not_engaged(tmp_path):
    """Engaging one topic doesn't engage others."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # Engage topic "greetings"
    await _call_from_thread(
        channel, _stream_message(content="@**TestBot** hi", subject="greetings")
    )
    channel.bus.publish_inbound.reset_mock()

    # Different topic "random" — not engaged
    channel._on_message_sync(
        _stream_message(content="hello", subject="random")
    )
    channel.bus.publish_inbound.assert_not_awaited()


async def test_dm_message_publishes_inbound(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    await _call_from_thread(channel, _dm_message())

    channel.bus.publish_inbound.assert_awaited_once()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.chat_id == "dm:42"
    assert msg.content == "hi there"


async def test_stream_not_in_allowed_list_no_mention(tmp_path):
    """Non-mentioned messages in non-configured streams are skipped."""
    config = _make_config(streams=["general"])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    channel._on_message_sync(_stream_message(
        display_recipient="random", content="hello"
    ))
    channel.bus.publish_inbound.assert_not_awaited()


async def test_mention_in_any_stream_works(tmp_path):
    """@mentions are processed even in streams not in the configured list."""
    config = _make_config(streams=["general"])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    await _call_from_thread(channel, _stream_message(
        display_recipient="random", content="@**Bot** help me"
    ))
    channel.bus.publish_inbound.assert_awaited_once()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.content == "help me"
    assert msg.chat_id == "random:greetings"


async def test_engaged_topic_in_non_monitored_stream(tmp_path):
    """Follow-ups in engaged topics work even in non-monitored streams."""
    config = _make_config(streams=["general"])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # @mention in "random" (not in configured streams) engages the topic
    await _call_from_thread(channel, _stream_message(
        display_recipient="random", content="@**Bot** hey"
    ))
    channel.bus.publish_inbound.assert_awaited_once()
    channel.bus.publish_inbound.reset_mock()

    # Follow-up without @mention in the same non-monitored stream topic
    await _call_from_thread(channel, _stream_message(
        display_recipient="random", content="follow up without mention"
    ))
    channel.bus.publish_inbound.assert_awaited_once()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.content == "follow up without mention"
    assert msg.chat_id == "random:greetings"


async def test_mention_stripped(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    await _call_from_thread(
        channel, _stream_message(content="@**TestBot** what is 2+2?")
    )

    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.content == "what is 2+2?"


async def test_empty_content_after_strip_ignored(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # Returns before run_coroutine_threadsafe — no deadlock
    channel._on_message_sync(_stream_message(content="@**TestBot**"))
    channel.bus.publish_inbound.assert_not_awaited()


async def test_is_allowed_enforced(tmp_path):
    config = _make_config(allow_from=["99"])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # sender_id=42 is not in allow_from=["99"], rejected by _handle_message
    await _call_from_thread(
        channel, _stream_message(sender_id=42, content="@**Bot** hello")
    )
    channel.bus.publish_inbound.assert_not_awaited()


async def test_is_allowed_permits(tmp_path):
    config = _make_config(allow_from=["42"])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    await _call_from_thread(
        channel, _stream_message(sender_id=42, content="@**Bot** hello")
    )
    channel.bus.publish_inbound.assert_awaited_once()


# -- Engaged topics persistence tests -----------------------------------------


async def test_first_mention_prepends_topic_history(tmp_path):
    """First @mention in a topic fetches and prepends message history."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # Mock get_messages to return prior conversation
    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [
            {"sender_full_name": "Alice", "content": "What can you do?"},
            {"sender_full_name": "Bob", "content": "Good question"},
        ],
    })

    await _call_from_thread(
        channel, _stream_message(content="@**TestBot** hi there")
    )

    msg = channel.bus.publish_inbound.call_args[0][0]
    assert "[Prior conversation in this topic]" in msg.content
    assert "Alice: What can you do?" in msg.content
    assert "Bob: Good question" in msg.content
    assert "hi there" in msg.content


async def test_second_message_does_not_prepend_history(tmp_path):
    """Subsequent messages in the same session don't re-fetch history."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [{"sender_full_name": "Alice", "content": "prior msg"}],
    })

    # First mention — engages and prepends history
    await _call_from_thread(
        channel, _stream_message(content="@**TestBot** first")
    )
    channel.bus.publish_inbound.reset_mock()
    channel._client.get_messages.reset_mock()

    # Second message — same session, no history re-fetch
    await _call_from_thread(
        channel, _stream_message(content="follow up")
    )
    channel._client.get_messages.assert_not_called()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.content == "follow up"
    assert "[Prior conversation" not in msg.content


async def test_history_injected_on_restart_for_engaged_topic(tmp_path):
    """After restart, first message in a previously-engaged topic gets history."""
    # Pre-populate engaged topics (simulating a restart)
    topics_file = tmp_path / "engaged_topics.json"
    topics_file.write_text(json.dumps(["general:greetings"]))

    channel = _make_channel(tmp_path=tmp_path)
    channel._engaged_topics_file = topics_file
    channel._load_engaged_topics()
    channel._loop = asyncio.get_running_loop()

    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [
            {"sender_full_name": "Alice", "content": "earlier message"},
        ],
    })

    # No @mention, but topic is already engaged from previous session
    await _call_from_thread(
        channel, _stream_message(content="hello again")
    )

    channel._client.get_messages.assert_called_once()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert "[Prior conversation in this topic]" in msg.content
    assert "Alice: earlier message" in msg.content
    assert "hello again" in msg.content


async def test_engaged_topics_persist_to_disk(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # Engage a topic
    await _call_from_thread(
        channel, _stream_message(content="@**Bot** hi", subject="persistent")
    )

    # Check file was written
    data = json.loads(channel._engaged_topics_file.read_text())
    assert "general:persistent" in data


async def test_engaged_topics_loaded_on_init(tmp_path):
    # Pre-populate the file
    topics_file = tmp_path / "engaged_topics.json"
    topics_file.write_text(json.dumps(["general:old-topic"]))

    channel = _make_channel(tmp_path=tmp_path)
    channel._engaged_topics_file = topics_file
    channel._load_engaged_topics()

    assert channel._is_engaged("general:old-topic")


# -- Send tests ----------------------------------------------------------------


async def test_send_stream_message(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._client = MagicMock()
    channel._client.send_message = MagicMock(return_value={"result": "success"})

    msg = OutboundMessage(
        channel="zulip",
        chat_id="general:greetings",
        content="hello!",
        metadata={"zulip": {"type": "stream", "stream": "general", "topic": "greetings"}},
    )
    await channel.send(msg)

    channel._client.send_message.assert_called_once_with({
        "type": "stream",
        "to": "general",
        "topic": "greetings",
        "content": "hello!",
    })


async def test_send_dm(tmp_path):
    channel = _make_channel(tmp_path=tmp_path)
    channel._client = MagicMock()
    channel._client.send_message = MagicMock(return_value={"result": "success"})

    msg = OutboundMessage(
        channel="zulip",
        chat_id="dm:42",
        content="hi back",
        metadata={"zulip": {"type": "private"}},
    )
    await channel.send(msg)

    channel._client.send_message.assert_called_once_with({
        "type": "direct",
        "to": [42],
        "content": "hi back",
    })


# -- Reaction handling tests ---------------------------------------------------


def _reaction_event(**overrides) -> dict:
    """Build a mock Zulip reaction event."""
    defaults = dict(
        type="reaction",
        op="add",
        emoji_name="+1",
        user_id=42,
        user={"email": "alice@test.com"},
        message_id=999,
    )
    defaults.update(overrides)
    return defaults


def _bot_message_response(**overrides) -> dict:
    """Build a mock message as returned by GET /messages/{id} for a bot message."""
    defaults = dict(
        id=999,
        type="stream",
        sender_email="bot@test.zulipchat.com",
        display_recipient="general",
        subject="greetings",
        content="1. marketing@store.com (12 emails)\n2. news@example.com (8 emails)",
    )
    defaults.update(overrides)
    return defaults


async def _call_reaction_from_thread(channel, event):
    """Call _on_reaction_sync from a thread, matching production behavior."""
    await asyncio.to_thread(channel._on_reaction_sync, event)


async def test_thumbs_up_reaction_forwards_approval(tmp_path):
    """A thumbs-up on a bot message forwards an approval to the agent bus."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    bot_msg = _bot_message_response()
    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [bot_msg],
    })

    await _call_reaction_from_thread(channel, _reaction_event())

    channel.bus.publish_inbound.assert_awaited_once()
    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.channel == "zulip"
    assert msg.chat_id == "general:greetings"
    assert msg.sender_id == "42"
    assert "reacted with" in msg.content
    assert "ONLY this message" in msg.content
    assert "marketing@store.com" in msg.content
    assert "news@example.com" in msg.content


async def test_thumbs_up_emoji_name_variants(tmp_path):
    """Both '+1' and 'thumbs_up' emoji names are recognized."""
    for emoji_name in ["+1", "thumbs_up", "thumbsup"]:
        channel = _make_channel(tmp_path=tmp_path)
        channel._loop = asyncio.get_running_loop()

        bot_msg = _bot_message_response()
        channel._client.get_messages = MagicMock(return_value={
            "result": "success",
            "messages": [bot_msg],
        })

        await _call_reaction_from_thread(
            channel, _reaction_event(emoji_name=emoji_name)
        )
        channel.bus.publish_inbound.assert_awaited_once()


async def test_non_thumbs_up_reaction_ignored(tmp_path):
    """Reactions other than thumbs-up are ignored."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    channel._on_reaction_sync(_reaction_event(emoji_name="heart"))
    channel.bus.publish_inbound.assert_not_awaited()


async def test_reaction_remove_ignored(tmp_path):
    """Reaction removal events (op='remove') are ignored."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    channel._on_reaction_sync(_reaction_event(op="remove"))
    channel.bus.publish_inbound.assert_not_awaited()


async def test_reaction_on_non_bot_message_ignored(tmp_path):
    """Thumbs-up on a message NOT sent by the bot is ignored."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    non_bot_msg = _bot_message_response(sender_email="alice@test.com")
    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [non_bot_msg],
    })

    await _call_reaction_from_thread(channel, _reaction_event())
    channel.bus.publish_inbound.assert_not_awaited()


async def test_reaction_from_non_allowed_sender_ignored(tmp_path):
    """Reactions from senders not in allow_from are ignored."""
    config = _make_config(allow_from=["99"])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    # user_id=42 is not in allow_from=["99"]
    channel._on_reaction_sync(_reaction_event(user_id=42))
    channel.bus.publish_inbound.assert_not_awaited()


async def test_reaction_allowed_when_wildcard_allow_from(tmp_path):
    """When allow_from is ['*'], all senders' reactions are processed."""
    config = _make_config(allow_from=["*"])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    bot_msg = _bot_message_response()
    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [bot_msg],
    })

    await _call_reaction_from_thread(channel, _reaction_event(user_id=42))
    channel.bus.publish_inbound.assert_awaited_once()


async def test_reaction_metadata_includes_message_id(tmp_path):
    """The forwarded message metadata includes the reacted-to message ID."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    bot_msg = _bot_message_response()
    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [bot_msg],
    })

    await _call_reaction_from_thread(channel, _reaction_event())

    msg = channel.bus.publish_inbound.call_args[0][0]
    assert msg.metadata["zulip"]["reaction_to_message_id"] == 999


async def test_reaction_denied_when_empty_allow_from(tmp_path):
    """When allow_from is empty list, reactions are denied (nanobot 0.1.4.post4 deny-by-default)."""
    config = _make_config(allow_from=[])
    channel = _make_channel(config, tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    bot_msg = _bot_message_response()
    channel._client.get_messages = MagicMock(return_value={
        "result": "success",
        "messages": [bot_msg],
    })

    await _call_reaction_from_thread(channel, _reaction_event(user_id=42))
    # Empty allow_from passes the reaction-level check (falsy), but
    # BaseChannel.is_allowed() denies all on empty list in 0.1.4.post4
    channel.bus.publish_inbound.assert_not_awaited()


async def test_reaction_fetch_message_failure_ignored(tmp_path):
    """If fetching the original message fails, the reaction is ignored gracefully."""
    channel = _make_channel(tmp_path=tmp_path)
    channel._loop = asyncio.get_running_loop()

    channel._client.get_messages = MagicMock(return_value={
        "result": "error",
        "msg": "not found",
    })

    await _call_reaction_from_thread(channel, _reaction_event())
    channel.bus.publish_inbound.assert_not_awaited()
