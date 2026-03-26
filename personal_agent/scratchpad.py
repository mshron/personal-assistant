"""Topic-based scratchpad — general-purpose working notes for the agent.

Standalone MCP server. Each topic is a JSONL file at
{SCRATCHPAD_DIR}/{topic}.jsonl. Entries have an optional subtopic key,
a freeform body, and an auto-set timestamp.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("scratchpad")

_DEFAULT_DIR = "/data/nanobot/workspace/scratchpad"


def _scratchpad_dir() -> Path:
    d = Path(os.environ.get("SCRATCHPAD_DIR", _DEFAULT_DIR))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _topic_path(topic: str) -> Path:
    """Return the JSONL file path for a topic. Sanitises the topic name."""
    safe = topic.strip().replace("/", "_").replace("..", "_")
    return _scratchpad_dir() / f"{safe}.jsonl"


# ---------------------------------------------------------------------------
# Core library functions (used by MCP tools and by email_scan directly)
# ---------------------------------------------------------------------------


def write_entry(topic: str, body: str, subtopic: str | None = None) -> dict:
    """Append an entry to a topic's JSONL file. Returns the written entry."""
    entry = {
        "subtopic": subtopic,
        "body": body,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    path = _topic_path(topic)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def read_entries(topic: str, subtopic: str | None = None) -> list[dict]:
    """Read entries from a topic, optionally filtered by subtopic."""
    path = _topic_path(topic)
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if subtopic is not None and entry.get("subtopic") != subtopic:
            continue
        entries.append(entry)
    return entries


def list_topics() -> list[dict]:
    """List all topics with entry count and latest timestamp."""
    d = _scratchpad_dir()
    topics = []
    for p in sorted(d.glob("*.jsonl")):
        name = p.stem
        lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        if not lines:
            continue
        # Get latest timestamp from last line
        latest = ""
        try:
            latest = json.loads(lines[-1]).get("created_at", "")
        except json.JSONDecodeError:
            pass
        topics.append({"topic": name, "entries": len(lines), "latest": latest})
    return topics


def list_subtopics(topic: str) -> list[dict]:
    """List distinct subtopics within a topic, with count and latest timestamp."""
    entries = read_entries(topic)
    subtopics: dict[str, dict] = {}
    for e in entries:
        key = e.get("subtopic")
        if key is None:
            key = "(no subtopic)"
        if key not in subtopics:
            subtopics[key] = {"subtopic": key, "count": 0, "latest": ""}
        subtopics[key]["count"] += 1
        subtopics[key]["latest"] = e.get("created_at", "")
    return sorted(subtopics.values(), key=lambda x: x["latest"], reverse=True)


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def scratchpad_write(topic: str, body: str, subtopic: str | None = None) -> str:
    """Write a note to the scratchpad.

    Parameters
    ----------
    topic:
        Topic name (e.g. "email", "research", "tasks"). Creates the topic
        if it doesn't exist.
    body:
        Freeform text to record.
    subtopic:
        Optional key for later lookup (e.g. a sender address, a task ID).
    """
    entry = write_entry(topic, body, subtopic)
    ts = entry["created_at"]
    sub = f" [{subtopic}]" if subtopic else ""
    return f"Written to {topic}{sub} at {ts}"


@mcp.tool()
async def scratchpad_lookup(topic: str, subtopic: str | None = None) -> str:
    """Look up entries in the scratchpad.

    Parameters
    ----------
    topic:
        Topic name to look up.
    subtopic:
        If given, returns all entries with this subtopic key.
        If blank, returns all entries in the topic.
    """
    entries = read_entries(topic, subtopic)
    if not entries:
        filter_msg = f" with subtopic '{subtopic}'" if subtopic else ""
        return f"No entries found in topic '{topic}'{filter_msg}."

    lines = []
    for e in entries:
        ts = e.get("created_at", "?")[:19]
        sub = f" [{e['subtopic']}]" if e.get("subtopic") else ""
        lines.append(f"[{ts}]{sub} {e['body']}")
    return "\n".join(lines)


@mcp.tool()
async def scratchpad_list(topic: str | None = None) -> str:
    """List topics or subtopics in the scratchpad.

    Parameters
    ----------
    topic:
        If given, lists subtopics within this topic.
        If blank, lists all topics.
    """
    if topic:
        subtopics = list_subtopics(topic)
        if not subtopics:
            return f"No entries in topic '{topic}'."
        lines = [f"Subtopics in '{topic}': {len(subtopics)}"]
        for s in subtopics:
            ts = s["latest"][:19] if s["latest"] else "?"
            lines.append(f"  {s['subtopic']}: {s['count']} entries (latest: {ts})")
        return "\n".join(lines)
    else:
        topics = list_topics()
        if not topics:
            return "Scratchpad is empty."
        lines = [f"Topics: {len(topics)}"]
        for t in topics:
            ts = t["latest"][:19] if t["latest"] else "?"
            lines.append(f"  {t['topic']}: {t['entries']} entries (latest: {ts})")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the scratchpad MCP server over stdio."""
    import asyncio
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
