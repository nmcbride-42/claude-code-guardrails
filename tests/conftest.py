"""Shared fixtures. Every hook subprocess gets its own config, event log and
backup directory under tmp_path, so a test run never reads or writes the
user's real guardrail state."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from claude_code_guardrails import guardrail as sg  # noqa: E402

GUARD_PATH = ROOT / "claude_code_guardrails" / "guardrail.py"


@pytest.fixture(autouse=True)
def default_config(monkeypatch):
    """In-process tests run against the built-in defaults."""
    sg.set_config({})
    yield
    sg.set_config({})


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def init_repo(repo):
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "test")
    git(repo, "config", "commit.gpgsign", "false")
    return repo


def hook_env(tmp_path, config=None, extra_path=None):
    cfg = tmp_path / "guardrail-config.json"
    cfg.write_text(json.dumps(config or {}))
    env = dict(os.environ,
               CLAUDE_GUARDRAIL_CONFIG=str(cfg),
               CLAUDE_GUARDRAIL_LOG=str(tmp_path / "events.jsonl"),
               CLAUDE_GUARDRAIL_BACKUP_DIR=str(tmp_path / "bk"))
    if extra_path:
        env["PATH"] = f"{extra_path}:{os.environ['PATH']}"
    return env


def run_hook(cmd, cwd, tmp_path, config=None, extra_path=None, src=GUARD_PATH, payload=None, **kw):
    """Invoke the hook exactly as Claude Code does: a subprocess with the JSON
    payload on stdin. Returns the CompletedProcess."""
    body = payload if payload is not None else json.dumps({"tool_input": {"command": cmd}, "cwd": str(cwd)})
    return subprocess.run([sys.executable, str(src)], input=body, capture_output=True, text=True,
                          env=hook_env(tmp_path, config, extra_path), timeout=60, **kw)


def stash_count(repo):
    out = subprocess.run(["git", "-C", str(repo), "stash", "list"], capture_output=True, text=True).stdout
    return len(out.splitlines())


@pytest.fixture
def dirty_repo(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "f").write_text("1")
    git(repo, "add", "f")
    git(repo, "commit", "-qm", "init")
    git(repo, "switch", "-qc", "work")   # not a protected branch
    (repo / "f").write_text("2")
    return repo


@pytest.fixture
def fake_ssh(tmp_path):
    """A fake `ssh` on PATH that records every invocation. Call it with ok=True
    for a reachable clean remote, ok=False for an unverifiable one."""
    def make(ok):
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        trace = tmp_path / "ssh-trace"
        trace.write_text("")
        fake = bindir / "ssh"
        fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> {trace}\nexit {0 if ok else 255}\n')
        fake.chmod(0o755)
        return bindir, trace
    return make
