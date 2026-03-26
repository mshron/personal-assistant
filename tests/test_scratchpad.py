"""Tests for the scratchpad module."""

from __future__ import annotations

import json

import pytest

from personal_agent.scratchpad import (
    list_subtopics,
    list_topics,
    read_entries,
    write_entry,
)


@pytest.fixture(autouse=True)
def scratchpad_dir(tmp_path, monkeypatch):
    """Point scratchpad at a temp directory for every test."""
    monkeypatch.setenv("SCRATCHPAD_DIR", str(tmp_path / "scratchpad"))
    return tmp_path / "scratchpad"


class TestWriteEntry:
    def test_creates_file_and_appends(self, scratchpad_dir):
        entry = write_entry("email", "status=pending", subtopic="a@b.com")
        assert entry["subtopic"] == "a@b.com"
        assert entry["body"] == "status=pending"
        assert "created_at" in entry

        path = scratchpad_dir / "email.jsonl"
        assert path.exists()
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["subtopic"] == "a@b.com"

    def test_appends_multiple(self, scratchpad_dir):
        write_entry("email", "first")
        write_entry("email", "second")
        path = scratchpad_dir / "email.jsonl"
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_no_subtopic(self, scratchpad_dir):
        entry = write_entry("research", "found interesting paper")
        assert entry["subtopic"] is None

    def test_sanitises_topic_name(self, scratchpad_dir):
        write_entry("bad/../topic", "test")
        assert (scratchpad_dir / "bad___topic.jsonl").exists()


class TestReadEntries:
    def test_read_all(self, scratchpad_dir):
        write_entry("t", "one", subtopic="a")
        write_entry("t", "two", subtopic="b")
        write_entry("t", "three")
        entries = read_entries("t")
        assert len(entries) == 3

    def test_filter_by_subtopic(self, scratchpad_dir):
        write_entry("t", "v1", subtopic="key")
        write_entry("t", "noise", subtopic="other")
        write_entry("t", "v2", subtopic="key")
        entries = read_entries("t", subtopic="key")
        assert len(entries) == 2
        assert entries[0]["body"] == "v1"
        assert entries[1]["body"] == "v2"

    def test_empty_topic(self, scratchpad_dir):
        entries = read_entries("nonexistent")
        assert entries == []

    def test_handles_malformed_lines(self, scratchpad_dir):
        path = scratchpad_dir / "bad.jsonl"
        scratchpad_dir.mkdir(parents=True, exist_ok=True)
        path.write_text('not json\n{"subtopic": null, "body": "ok", "created_at": "x"}\n')
        entries = read_entries("bad")
        assert len(entries) == 1
        assert entries[0]["body"] == "ok"


class TestListTopics:
    def test_empty(self, scratchpad_dir):
        assert list_topics() == []

    def test_multiple_topics(self, scratchpad_dir):
        write_entry("email", "test")
        write_entry("research", "test")
        topics = list_topics()
        names = [t["topic"] for t in topics]
        assert "email" in names
        assert "research" in names

    def test_entry_count(self, scratchpad_dir):
        write_entry("t", "one")
        write_entry("t", "two")
        write_entry("t", "three")
        topics = list_topics()
        assert topics[0]["entries"] == 3


class TestListSubtopics:
    def test_empty_topic(self, scratchpad_dir):
        assert list_subtopics("nonexistent") == []

    def test_groups_by_subtopic(self, scratchpad_dir):
        write_entry("email", "v1", subtopic="a@b.com")
        write_entry("email", "v2", subtopic="a@b.com")
        write_entry("email", "v1", subtopic="c@d.com")
        write_entry("email", "note without subtopic")
        subs = list_subtopics("email")
        by_key = {s["subtopic"]: s for s in subs}
        assert by_key["a@b.com"]["count"] == 2
        assert by_key["c@d.com"]["count"] == 1
        assert by_key["(no subtopic)"]["count"] == 1


class TestMCPTools:
    """Test the MCP tool wrappers."""

    async def test_scratchpad_write(self, scratchpad_dir):
        from personal_agent.scratchpad import scratchpad_write

        result = await scratchpad_write("test", "hello", subtopic="key1")
        assert "Written to test [key1]" in result
        entries = read_entries("test", subtopic="key1")
        assert len(entries) == 1

    async def test_scratchpad_lookup_all(self, scratchpad_dir):
        from personal_agent.scratchpad import scratchpad_lookup

        write_entry("t", "one", subtopic="a")
        write_entry("t", "two", subtopic="b")
        result = await scratchpad_lookup("t")
        assert "one" in result
        assert "two" in result

    async def test_scratchpad_lookup_filtered(self, scratchpad_dir):
        from personal_agent.scratchpad import scratchpad_lookup

        write_entry("t", "match", subtopic="key")
        write_entry("t", "noise", subtopic="other")
        result = await scratchpad_lookup("t", subtopic="key")
        assert "match" in result
        assert "noise" not in result

    async def test_scratchpad_lookup_empty(self, scratchpad_dir):
        from personal_agent.scratchpad import scratchpad_lookup

        result = await scratchpad_lookup("empty")
        assert "No entries" in result

    async def test_scratchpad_list_topics(self, scratchpad_dir):
        from personal_agent.scratchpad import scratchpad_list

        write_entry("email", "test")
        write_entry("research", "test")
        result = await scratchpad_list()
        assert "email" in result
        assert "research" in result

    async def test_scratchpad_list_subtopics(self, scratchpad_dir):
        from personal_agent.scratchpad import scratchpad_list

        write_entry("email", "v1", subtopic="a@b.com")
        write_entry("email", "v2", subtopic="c@d.com")
        result = await scratchpad_list(topic="email")
        assert "a@b.com" in result
        assert "c@d.com" in result
