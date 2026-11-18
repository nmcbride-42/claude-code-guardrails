"""The hook contract: JSON on stdin, exit 2 + stderr to block, fail open on a
malformed payload, fail closed on an internal error or a broken config."""
import io
import json
import subprocess
import sys

import pytest

from conftest import ROOT, git, hook_env, init_repo, run_hook, sg

_RF = "-" + "rf"


@pytest.mark.parametrize("garbage", ["", "not json{{{", '{"tool_name": 42}', "[1, 2]",
                                     '{"tool_input": "x"}', '{"tool_input": {"command": 7}}'])
def test_fail_open_on_malformed_payload(garbage, tmp_path):
    p = run_hook(None, tmp_path, tmp_path, payload=garbage)
    assert p.returncode == 0, p.stderr


def test_block_message_goes_to_stderr(tmp_path):
    p = run_hook("rm " + _RF + " /", tmp_path, tmp_path)
    assert p.returncode == 2
    assert p.stderr.startswith("SAFETY GUARDRAIL: Blocked") and p.stdout == ""
    events = [json.loads(ln) for ln in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert events[-1]["mode"] == "hard_block"


def test_benign_command_passes_silently(tmp_path):
    p = run_hook("ls -la && git status", tmp_path, tmp_path)
    assert p.returncode == 0 and p.stderr == ""


def test_blocked_command_never_executes_in_process(monkeypatch):
    monkeypatch.setenv("CLAUDE_GUARDRAIL_LOG", "none")
    monkeypatch.setattr(sg.subprocess, "run", lambda *a, **k: pytest.fail("a blocked command must not run anything"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "rm --recursive /etc"}})))
    with pytest.raises(SystemExit) as result:
        sg.main()
    assert result.value.code == 2


def test_invalid_config_fails_closed(tmp_path):
    env = hook_env(tmp_path)
    cfg = tmp_path / "broken.json"
    cfg.write_text("{not json")
    env["CLAUDE_GUARDRAIL_CONFIG"] = str(cfg)
    p = subprocess.run([sys.executable, "-m", "claude_code_guardrails"], cwd=ROOT, env=env, text=True,
                       capture_output=True, input=json.dumps({"tool_input": {"command": "ls"}}), timeout=30)
    assert p.returncode == 2 and "cannot parse config" in p.stderr


def test_missing_explicit_config_fails_closed(tmp_path):
    env = hook_env(tmp_path)
    env["CLAUDE_GUARDRAIL_CONFIG"] = str(tmp_path / "nope.json")
    p = subprocess.run([sys.executable, "-m", "claude_code_guardrails"], cwd=ROOT, env=env, text=True,
                       capture_output=True, input=json.dumps({"tool_input": {"command": "ls"}}), timeout=30)
    assert p.returncode == 2 and "does not exist" in p.stderr


def test_load_config_merges_over_defaults(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"_comment": "ignored", "remote": {"allowed_hosts": ["devbox"]}}))
    c = sg.load_config(str(cfg))
    assert c["remote"] == {"mode": "stash", "allowed_hosts": ["devbox"]}
    assert c["protected_branches"] == ["main", "master"]
    cfg.write_text(json.dumps({"remote": {"mode": "yolo"}}))
    with pytest.raises(sg.ConfigError):
        sg.load_config(str(cfg))
    cfg.write_text(json.dumps({"protected_paths": "/srv"}))
    with pytest.raises(sg.ConfigError):
        sg.load_config(str(cfg))


@pytest.fixture
def repo_on_main(tmp_path):
    repo = init_repo(tmp_path / "repo")
    (repo / "f").write_text("1")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    return repo


def test_commit_on_protected_branch_is_blocked(repo_on_main, tmp_path):
    p = run_hook("git commit -qam 'change'", repo_on_main, tmp_path)
    assert p.returncode == 2 and "protected branch 'main'" in p.stderr


def test_chained_branch_then_commit_is_still_blocked(repo_on_main, tmp_path):
    p = run_hook("git switch -c topic && git commit -qam 'change'", repo_on_main, tmp_path)
    assert p.returncode == 2


def test_commit_on_topic_branch_is_allowed(repo_on_main, tmp_path):
    git(repo_on_main, "switch", "-qc", "topic")
    p = run_hook("git commit -qam 'change'", repo_on_main, tmp_path)
    assert p.returncode == 0, p.stderr


def test_commit_guard_can_be_disabled(repo_on_main, tmp_path):
    p = run_hook("git commit -qam 'change'", repo_on_main, tmp_path,
                 config={"block_commit_on_protected_branch": False})
    assert p.returncode == 0, p.stderr


def test_fresh_repo_without_commits_is_still_guarded(tmp_path):
    repo = init_repo(tmp_path / "fresh")
    p = run_hook("git commit -qm first", repo, tmp_path)
    assert p.returncode == 2


def test_protected_repo_from_config_end_to_end(tmp_path):
    target = tmp_path / "work" / "my-app"
    target.mkdir(parents=True)
    cfg = {"protected_repos": [{"name": "my-app", "paths": [str(target)]}]}
    p = run_hook(f"rm {_RF} {target}", tmp_path, tmp_path, config=cfg)
    assert p.returncode == 2 and "my-app" in p.stderr
    assert target.exists()


def test_dash_c_commit_on_protected_branch_is_blocked(repo_on_main, tmp_path):
    elsewhere = init_repo(tmp_path / "elsewhere")
    git(elsewhere, "switch", "-qc", "topic")   # the hook's cwd is on a topic branch
    p = run_hook(f"git -C {repo_on_main} commit -qam 'change'", elsewhere, tmp_path)
    assert p.returncode == 2 and "protected branch 'main'" in p.stderr
    p = run_hook(f"git -C {elsewhere} commit -qam 'change'", repo_on_main, tmp_path)
    assert p.returncode == 0, p.stderr


def test_dash_c_commit_message_prose_is_not_scanned(tmp_path):
    repo = init_repo(tmp_path / "r")
    git(repo, "switch", "-qc", "topic")
    p = run_hook(f"git -C {repo} commit -qm 'docs: never run rm {_RF} / here'", tmp_path, tmp_path)
    assert p.returncode == 0, p.stderr


_P = "pu" + "sh"


@pytest.fixture
def tracked_repo(repo_on_main, tmp_path):
    """repo_on_main with an `origin` remote and main tracking origin/main."""
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, capture_output=True)
    git(repo_on_main, "remote", "add", "origin", str(remote))
    git(repo_on_main, _P, "-q", "-u", "origin", "main")
    return repo_on_main


@pytest.mark.parametrize("cmd", [f"git {_P}", f"git {_P} origin", f"git {_P} -u origin HEAD",
                                 f"git {_P} --all origin", f"git {_P} --follow-tags"])
def test_implicit_push_to_protected_branch_is_blocked(cmd, tracked_repo, tmp_path):
    p = run_hook(cmd, tracked_repo, tmp_path)
    assert p.returncode == 2 and "protected branch 'main'" in p.stderr, p.stderr


def test_implicit_push_via_dash_c_is_blocked(tracked_repo, tmp_path):
    p = run_hook(f"git -C {tracked_repo} {_P}", tmp_path, tmp_path)
    assert p.returncode == 2 and "protected branch 'main'" in p.stderr, p.stderr


def test_implicit_push_of_a_branch_tracking_main_is_blocked(tracked_repo, tmp_path):
    git(tracked_repo, "switch", "-qc", "topic", "--track", "origin/main")
    p = run_hook(f"git {_P}", tracked_repo, tmp_path)
    assert p.returncode == 2 and "protected branch 'main'" in p.stderr, p.stderr


@pytest.mark.parametrize("cmd", [f"git {_P}", f"git {_P} origin", f"git {_P} -u origin HEAD",
                                 f"git {_P} -u origin topic", f"git {_P} --tags origin"])
def test_push_from_an_untracked_topic_branch_is_allowed(cmd, tracked_repo, tmp_path):
    git(tracked_repo, "switch", "-qc", "topic")
    p = run_hook(cmd, tracked_repo, tmp_path)
    assert p.returncode == 0, p.stderr


def test_push_all_is_allowed_without_a_local_protected_branch(tmp_path):
    repo = init_repo(tmp_path / "r")
    git(repo, "switch", "-qc", "topic")
    (repo / "f").write_text("1")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    p = run_hook(f"git {_P} --all origin", repo, tmp_path)
    assert p.returncode == 0, p.stderr
