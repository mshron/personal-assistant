import json
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def log_file(tmp_path):
    return tmp_path / "agent.jsonl"


@pytest.fixture
def log_server(log_file):
    """Start the log service as a subprocess."""
    proc = subprocess.Popen(
        [sys.executable, "log-service/main.py"],
        env={
            **dict(__import__("os").environ),
            "LOG_FILE": str(log_file),
            "LOG_PORT": "18091",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1)
    yield proc
    proc.terminate()
    proc.wait()


def test_log_appends_json_line(log_server, log_file):
    response = httpx.post(
        "http://localhost:18091/log",
        json={"event": "tool_call", "tool": "web_search", "args": {"query": "test"}},
    )
    assert response.status_code == 200
    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event"] == "tool_call"
    assert "timestamp" in entry


def test_log_multiple_entries(log_server, log_file):
    for i in range(3):
        httpx.post("http://localhost:18091/log", json={"seq": i})
    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 3


def test_log_rejects_non_json(log_server):
    response = httpx.post(
        "http://localhost:18091/log",
        content=b"not json",
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 400


def test_health_endpoint(log_server):
    response = httpx.get("http://localhost:18091/health")
    assert response.status_code == 200
