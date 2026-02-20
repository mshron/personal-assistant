"""Zulip channel for the personal agent.

Bridges the sync-only Zulip SDK to nanobot's async BaseChannel via a daemon
thread and asyncio.run_coroutine_threadsafe.

Threading model: the bot subscribes to configured streams and receives ALL
messages. It tracks "engaged topics" — topics where it has been @mentioned.
Messages in engaged topics are forwarded to the agent even without a mention.
Engaged topics persist to disk so they survive restarts.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import zulip
from loguru import logger

from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.base import BaseChannel

# Default path for persisting engaged topics (overridable via ENGAGED_TOPICS_FILE)
_DEFAULT_ENGAGED_TOPICS_FILE = "/data/zulip_engaged_topics.json"


@dataclass
class ZulipConfig:
    site: str
    email: str
    api_key: str
    streams: list[str]
    allow_from: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> ZulipConfig:
        import os

        site = os.environ.get("ZULIP_SITE", "")
        email = os.environ.get("ZULIP_EMAIL", "")
        api_key = os.environ.get("ZULIP_API_KEY", "")
        streams_raw = os.environ.get("ZULIP_STREAMS", "")
        allow_raw = os.environ.get("ZULIP_ALLOW_FROM", "")

        missing = []
        if not site:
            missing.append("ZULIP_SITE")
        if not email:
            missing.append("ZULIP_EMAIL")
        if not api_key:
            missing.append("ZULIP_API_KEY")
        if missing:
            raise ValueError(f"Missing required env vars: {', '.join(missing)}")

        streams = [s.strip() for s in streams_raw.split(",") if s.strip()]
        allow_from = [s.strip() for s in allow_raw.split(",") if s.strip()]

        return cls(
            site=site,
            email=email,
            api_key=api_key,
            streams=streams,
            allow_from=allow_from,
        )


class ZulipChannel(BaseChannel):
    name = "zulip"

    def __init__(self, config: ZulipConfig, bus: MessageBus):
        super().__init__(config, bus)
        self._client = zulip.Client(
            email=config.email,
            api_key=config.api_key,
            site=config.site,
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._listener_thread: threading.Thread | None = None
        # Pattern to strip bot mention like @**BotName**
        self._mention_re = re.compile(r"@\*\*[^*]+\*\*\s*")
        # Topics where the bot has been @mentioned — persisted to disk
        self._engaged_topics: set[str] = set()
        self._engaged_topics_lock = threading.Lock()
        self._engaged_topics_file = Path(
            os.environ.get("ENGAGED_TOPICS_FILE", _DEFAULT_ENGAGED_TOPICS_FILE)
        )
        # Topics where history has already been injected this session
        self._history_injected: set[str] = set()

    def _load_engaged_topics(self) -> None:
        """Load engaged topics from disk."""
        if self._engaged_topics_file.exists():
            try:
                data = json.loads(self._engaged_topics_file.read_text())
                self._engaged_topics = set(data)
                logger.info(f"Loaded {len(self._engaged_topics)} engaged topics from disk")
            except (json.JSONDecodeError, TypeError):
                logger.warning("Could not parse engaged topics file, starting fresh")
                self._engaged_topics = set()

    def _save_engaged_topics(self) -> None:
        """Persist engaged topics to disk."""
        self._engaged_topics_file.parent.mkdir(parents=True, exist_ok=True)
        self._engaged_topics_file.write_text(json.dumps(sorted(self._engaged_topics)))

    def _engage_topic(self, chat_id: str) -> bool:
        """Mark a topic as engaged (thread-safe). Returns True if newly engaged."""
        with self._engaged_topics_lock:
            if chat_id not in self._engaged_topics:
                self._engaged_topics.add(chat_id)
                self._save_engaged_topics()
                logger.info(f"Engaged topic: {chat_id}")
                return True
            return False

    def _is_engaged(self, chat_id: str) -> bool:
        """Check if a topic is engaged (thread-safe)."""
        with self._engaged_topics_lock:
            return chat_id in self._engaged_topics

    def _has_mention(self, content: str) -> bool:
        """Check if content contains a bot @mention."""
        return bool(self._mention_re.search(content))

    def _fetch_topic_history(self, stream: str, topic: str, limit: int = 50) -> str:
        """Fetch prior messages in a topic and format as context string.

        Called synchronously from the listener thread when a topic is first
        engaged. Returns an empty string if no history or on error.
        """
        result = self._client.get_messages({
            "anchor": "newest",
            "narrow": [
                {"operator": "channel", "operand": stream},
                {"operator": "topic", "operand": topic},
            ],
            "num_before": limit,
            "num_after": 0,
        })
        if result.get("result") != "success":
            logger.warning(f"Failed to fetch topic history: {result}")
            return ""

        messages = result.get("messages", [])
        if not messages:
            return ""

        lines = []
        for msg in messages:
            sender = msg.get("sender_full_name", "unknown")
            content = msg.get("content", "")
            lines.append(f"{sender}: {content}")

        return "\n".join(lines)

    def _subscribe_to_streams(self) -> None:
        """Subscribe the bot to configured streams on the Zulip server."""
        if not self.config.streams:
            return
        subscriptions = [{"name": s} for s in self.config.streams]
        result = self._client.add_subscriptions(subscriptions)
        if result.get("result") == "success":
            logger.info(f"Subscribed to streams: {self.config.streams}")
        else:
            logger.error(f"Failed to subscribe to streams: {result}")

    async def start(self) -> None:
        self._running = True
        self._loop = asyncio.get_running_loop()
        self._load_engaged_topics()

        # Subscribe bot to streams so it receives all messages, not just @mentions
        await asyncio.to_thread(self._subscribe_to_streams)

        self._listener_thread = threading.Thread(
            target=self._listen_sync,
            daemon=True,
        )
        self._listener_thread.start()
        logger.info(f"Zulip channel started, listening on streams: {self.config.streams}")

        # Keep the coroutine alive while channel is running
        while self._running:
            await asyncio.sleep(1)

    def _listen_sync(self) -> None:
        """Blocking listener that runs in a daemon thread."""
        try:
            def event_callback(event: dict[str, Any]) -> None:
                if event["type"] == "message":
                    self._on_message_sync(event["message"])

            self._client.call_on_each_event(
                event_callback,
                event_types=["message"],
                narrow=[],
                all_public_streams=True,
            )
        except Exception as e:
            logger.error(f"Zulip listener error: {e}")
            self._running = False

    def _on_message_sync(self, message: dict[str, Any]) -> None:
        """Called for each incoming message (in the listener thread)."""
        logger.info(
            f"Received message from {message.get('sender_email')} "
            f"in {message.get('display_recipient')}:{message.get('subject')}: "
            f"{message.get('content', '')[:80]}"
        )

        # Skip own messages
        if message.get("sender_email") == self.config.email:
            return

        msg_type = message.get("type", "")

        # Build chat_id
        if msg_type == "stream":
            stream = message.get("display_recipient", "")
            topic = message.get("subject", "")
            chat_id = f"{stream}:{topic}"
        else:
            # DM — always process
            chat_id = f"dm:{message['sender_id']}"

        raw_content = message.get("content", "")

        # For stream messages, check engagement.
        # @mentions work in ANY stream; non-mention messages only in
        # configured streams where the topic is already engaged.
        newly_engaged = False
        if msg_type == "stream":
            has_mention = self._has_mention(raw_content)
            in_monitored_stream = (
                not self.config.streams or stream in self.config.streams
            )
            if has_mention:
                newly_engaged = self._engage_topic(chat_id)
            elif not in_monitored_stream:
                # Non-mention in a stream we don't monitor — skip
                return
            elif not self._is_engaged(chat_id):
                # Non-mention, monitored stream, but topic not engaged — skip
                return

        # Strip bot mention from content
        content = self._mention_re.sub("", raw_content).strip()

        if not content:
            return

        # On first message in a topic this session, prepend history for context
        if msg_type == "stream" and chat_id not in self._history_injected:
            self._history_injected.add(chat_id)
            stream = message.get("display_recipient", "")
            topic = message.get("subject", "")
            history = self._fetch_topic_history(stream, topic)
            if history:
                content = (
                    f"[Prior conversation in this topic]\n"
                    f"{history}\n\n"
                    f"[New message]\n"
                    f"{content}"
                )
                logger.info(f"Prepended topic history for {chat_id}")

        sender_id = str(message["sender_id"])

        metadata = {
            "zulip": {
                "type": msg_type,
                "topic": message.get("subject"),
                "stream": message.get("display_recipient") if msg_type == "stream" else None,
                "sender_email": message.get("sender_email"),
            }
        }

        # Bridge from sync thread to async event loop
        future = asyncio.run_coroutine_threadsafe(
            self._handle_message(
                sender_id=sender_id,
                chat_id=chat_id,
                content=content,
                metadata=metadata,
            ),
            self._loop,
        )
        # Wait for it to complete so exceptions surface
        try:
            future.result(timeout=30)
        except Exception as e:
            logger.error(f"Error handling Zulip message: {e}")

    async def stop(self) -> None:
        self._running = False

    async def send(self, msg: OutboundMessage) -> None:
        zulip_meta = msg.metadata.get("zulip", {})
        msg_type = zulip_meta.get("type", "stream")

        if msg_type == "stream":
            stream = zulip_meta.get("stream", "")
            topic = zulip_meta.get("topic", "")
            # Fallback: parse from chat_id if metadata is missing
            if not stream and ":" in msg.chat_id:
                stream, topic = msg.chat_id.split(":", 1)
            request = {
                "type": "stream",
                "to": stream,
                "topic": topic,
                "content": msg.content,
            }
        else:
            # DM — extract sender_id from chat_id "dm:{sender_id}"
            sender_id = msg.chat_id.removeprefix("dm:")
            request = {
                "type": "direct",
                "to": [int(sender_id)],
                "content": msg.content,
            }

        result = await asyncio.to_thread(self._client.send_message, request)
        if result.get("result") != "success":
            logger.error(f"Zulip send failed: {result}")
