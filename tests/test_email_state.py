"""Tests for personal_agent.email.state — SubscriptionStore."""

from __future__ import annotations

import json
import threading
from datetime import date
from pathlib import Path

from personal_agent.email.state import ScanRecord, SenderRecord, SubscriptionStore


# ------------------------------------------------------------------
# Load / save roundtrip
# ------------------------------------------------------------------


def test_load_save_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "state.json"
    store = SubscriptionStore(path=p)
    store.load()
    store.upsert_sender("a@example.com", status="active", email_count=3)
    store.add_scan(date(2026, 1, 1), date(2026, 1, 31), candidates_found=5)

    # Re-load from disk in a fresh instance
    store2 = SubscriptionStore(path=p)
    store2.load()

    rec = store2.get_sender("a@example.com")
    assert rec is not None
    assert rec.status == "active"
    assert rec.email_count == 3

    scans = store2.get_scans()
    assert len(scans) == 1
    assert scans[0].candidates_found == 5


# ------------------------------------------------------------------
# Missing file creates empty state
# ------------------------------------------------------------------


def test_load_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "nonexistent" / "state.json"
    store = SubscriptionStore(path=p)
    store.load()
    assert store.list_senders() == []
    assert store.get_scans() == []


# ------------------------------------------------------------------
# upsert_sender: create and update
# ------------------------------------------------------------------


def test_upsert_sender_creates(tmp_path: Path) -> None:
    store = SubscriptionStore(path=tmp_path / "s.json")
    store.load()
    rec = store.upsert_sender("b@example.com", status="pending", email_count=1)
    assert rec.sender == "b@example.com"
    assert rec.status == "pending"
    assert rec.email_count == 1


def test_upsert_sender_updates(tmp_path: Path) -> None:
    store = SubscriptionStore(path=tmp_path / "s.json")
    store.load()
    store.upsert_sender("c@example.com", status="active", email_count=2)
    updated = store.upsert_sender("c@example.com", status="unsubscribed", email_count=5)
    assert updated.status == "unsubscribed"
    assert updated.email_count == 5
    # first_seen should remain from original creation
    original = store.get_sender("c@example.com")
    assert original is not None
    assert original.first_seen == updated.first_seen


# ------------------------------------------------------------------
# list_senders filtering
# ------------------------------------------------------------------


def test_list_senders_no_filter(tmp_path: Path) -> None:
    store = SubscriptionStore(path=tmp_path / "s.json")
    store.load()
    store.upsert_sender("a@x.com", status="active")
    store.upsert_sender("b@x.com", status="skipped")
    assert len(store.list_senders()) == 2


def test_list_senders_by_status(tmp_path: Path) -> None:
    store = SubscriptionStore(path=tmp_path / "s.json")
    store.load()
    store.upsert_sender("a@x.com", status="active")
    store.upsert_sender("b@x.com", status="skipped")
    store.upsert_sender("c@x.com", status="active")
    active = store.list_senders(status="active")
    assert len(active) == 2
    assert all(r.status == "active" for r in active)
    skipped = store.list_senders(status="skipped")
    assert len(skipped) == 1


# ------------------------------------------------------------------
# Scan recording and is_scanned
# ------------------------------------------------------------------


def test_add_scan_and_is_scanned(tmp_path: Path) -> None:
    store = SubscriptionStore(path=tmp_path / "s.json")
    store.load()
    assert not store.is_scanned(date(2026, 1, 1), date(2026, 1, 31))
    store.add_scan(date(2026, 1, 1), date(2026, 1, 31), candidates_found=3)
    assert store.is_scanned(date(2026, 1, 1), date(2026, 1, 31))
    assert not store.is_scanned(date(2026, 2, 1), date(2026, 2, 28))


def test_get_scans_returns_scan_records(tmp_path: Path) -> None:
    store = SubscriptionStore(path=tmp_path / "s.json")
    store.load()
    store.add_scan(date(2026, 3, 1), date(2026, 3, 7), candidates_found=10)
    scans = store.get_scans()
    assert len(scans) == 1
    assert isinstance(scans[0], ScanRecord)
    assert scans[0].after == "2026-03-01"
    assert scans[0].before == "2026-03-07"
    assert scans[0].candidates_found == 10


# ------------------------------------------------------------------
# Concurrent save safety (file not corrupted)
# ------------------------------------------------------------------


def test_concurrent_saves_no_corruption(tmp_path: Path) -> None:
    """Multiple threads saving simultaneously should not corrupt the file."""
    p = tmp_path / "s.json"
    store = SubscriptionStore(path=p)
    store.load()

    errors: list[Exception] = []

    def writer(i: int) -> None:
        try:
            store.upsert_sender(f"user{i}@example.com", status="active", email_count=i)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors during concurrent writes: {errors}"

    # File must be valid JSON after all writes
    raw = json.loads(p.read_text(encoding="utf-8"))
    assert "senders" in raw
    assert "scans" in raw
    # At least some senders should have been persisted (exact count depends
    # on race ordering, but the file must be valid).
    assert len(raw["senders"]) > 0


# ------------------------------------------------------------------
# Parent directory creation
# ------------------------------------------------------------------


def test_save_creates_parent_dirs(tmp_path: Path) -> None:
    p = tmp_path / "deep" / "nested" / "state.json"
    store = SubscriptionStore(path=p)
    store.load()
    store.upsert_sender("d@x.com", status="active")
    assert p.exists()
    raw = json.loads(p.read_text(encoding="utf-8"))
    assert "d@x.com" in raw["senders"]
