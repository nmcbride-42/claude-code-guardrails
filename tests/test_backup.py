"""Auto-backup before recoverable-but-destructive git ops.

Two properties are pinned here:
  1. detection: a destructive pattern that is only quoted data never triggers a
     backup; a real top-level op (including one hidden in `bash -c`, a pipe to
     `sh`, or command substitution) always does;
  2. the backup never touches the working tree: tracked changes become a stored
     stash entry (`git stash create` + `git stash store`) and untracked files go
     to a tar.gz. Nothing is removed, so no live file ever disappears.
"""
import json
import os
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

from conftest import GUARD_PATH, git, hook_env, init_repo, run_hook, sg, stash_count

# Files a running application might keep uncommitted in its own checkout.
_LIVE_FILES = [
    "state/pending.json",
    "state/.paused",
    "notes/2026-01-01.md",
    "cache/session/current.md",
]

_COMMIT_PROSE_1 = (
    "git commit -q -m \"guard: ssh suffix\n\nssh devbox 'x' ; a local suffix\n"
    "  git reset --hard' still backs up first.\""
)
_COMMIT_PROSE_2 = (
    "git commit -q -F - <<'EOF'\nguard: chains\n\n"
    "  ending in a local git reset --hard still backs up first.\nEOF"
)
_QUOTED_DATA_CMDS = [_COMMIT_PROSE_1, _COMMIT_PROSE_2,
                     "echo 'git reset --hard' > /dev/null",
                     "printf '%s\\n' \"git clean -fd\"",
                     "cat <<'EOF'\nnote: git reset --hard is only text here\nEOF",
                     "git commit -q --message='about git checkout -f main'"]

# Quoted text handed to something that can execute it stays fail-safe.
_HIDDEN_REAL_OPS = [
    "/bin/bash -c 'git reset --hard'",
    "cat <<EOF | sh\n$(git reset --hard)\nEOF",
    "cat <<EOF\n`git reset --hard`\nEOF",
    "/usr/bin/python3 -c \"import os; os.system('git reset --hard')\"",
    "echo \"$(git reset --hard \"HEAD\")\"",
]

_REAL_OPS = [
    "git reset --hard",
    "git checkout -f main",
    "git clean -fd",
    "git checkout -- f",
    "true && git reset --hard",
    "true; git checkout -f main",
    "echo hi | git reset --hard",
    "git reset \"--hard\"",
    "bash -c 'git reset --hard'",
    "echo 'git reset --hard' | sh",
    "echo \"$(git reset --hard)\"",
    "git commit -qm 'x' && git reset --hard",
]


@pytest.fixture
def live_repo(tmp_path):
    """Disposable repo, dirty in tracked, untracked and live-state paths."""
    repo = init_repo(tmp_path / "repo")
    (repo / "f").write_text("1")
    (repo / "state").mkdir()
    (repo / "state/tracked.json").write_text("1")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    git(repo, "switch", "-qc", "work")   # not main: the commit guard blocks commits there
    (repo / "f").write_text("2")
    (repo / "state/tracked.json").write_text("2")
    (repo / "u.txt").write_text("untracked")
    for rel in _LIVE_FILES:
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("live " + rel)
    return repo


def _tars(tmp_path):
    return sorted((tmp_path / "bk").glob("*-untracked.tar.gz")) if (tmp_path / "bk").exists() else []


def _snapshot(repo):
    snap = {}
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            fp = os.path.join(root, f)
            st = os.lstat(fp)
            snap[fp] = (st.st_mtime_ns, st.st_size, Path(fp).read_bytes())
    return snap


def _status(repo):
    return subprocess.run(["git", "-C", str(repo), "status", "--porcelain=v1"],
                          capture_output=True, text=True).stdout


@pytest.mark.parametrize("cmd", _QUOTED_DATA_CMDS)
def test_destructive_pattern_in_quoted_data_never_backs_up(cmd, live_repo, tmp_path):
    p = run_hook(cmd, live_repo, tmp_path)
    assert stash_count(live_repo) == 0, p.stderr
    assert _tars(tmp_path) == []
    assert p.returncode == 0, p.stderr
    assert (live_repo / "f").read_text() == "2"


@pytest.mark.parametrize("cmd", _REAL_OPS + _HIDDEN_REAL_OPS)
def test_real_destructive_op_backs_up(cmd, live_repo, tmp_path):
    p = run_hook(cmd, live_repo, tmp_path)
    assert p.returncode == 0, p.stderr
    assert stash_count(live_repo) == 1, p.stderr
    assert len(_tars(tmp_path)) == 1, p.stderr
    assert "backed up tracked changes" in p.stderr and "untracked files to" in p.stderr


def test_clean_tree_is_left_alone(tmp_path):
    repo = init_repo(tmp_path / "clean")
    (repo / "f").write_text("1")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    p = run_hook("git reset --hard", repo, tmp_path)
    assert p.returncode == 0 and p.stderr == "" and stash_count(repo) == 0


@pytest.mark.parametrize("cmd", ["git reset --hard", "git checkout -f main", "git clean -fd"])
def test_hook_never_touches_the_working_tree(cmd, live_repo, tmp_path):
    before, status_before = _snapshot(live_repo), _status(live_repo)
    p = run_hook(cmd, live_repo, tmp_path)
    assert p.returncode == 0 and stash_count(live_repo) == 1, p.stderr
    assert _snapshot(live_repo) == before          # contents AND mtimes
    assert _status(live_repo) == status_before     # index untouched too


def test_tracked_changes_recoverable_after_the_real_reset(live_repo, tmp_path):
    p = run_hook("git reset --hard", live_repo, tmp_path)
    assert stash_count(live_repo) == 1, p.stderr
    git(live_repo, "reset", "--hard")              # the real op
    assert (live_repo / "f").read_text() == "1"
    git(live_repo, "stash", "apply", "stash@{0}")
    assert (live_repo / "f").read_text() == "2"
    assert (live_repo / "state/tracked.json").read_text() == "2"


def test_untracked_files_recoverable_after_the_real_clean(live_repo, tmp_path):
    p = run_hook("git clean -fd", live_repo, tmp_path)
    assert p.returncode == 0, p.stderr
    tars = _tars(tmp_path)
    assert len(tars) == 1 and oct(tars[0].stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "bk").stat().st_mode & 0o777) == "0o700"
    git(live_repo, "clean", "-fd")                 # the real op
    assert not (live_repo / "u.txt").exists() and not (live_repo / _LIVE_FILES[0]).exists()
    with tarfile.open(tars[0]) as tf:
        if hasattr(tarfile, "data_filter"):
            tf.extractall(live_repo, filter="data")
        else:
            tf.extractall(live_repo)
    assert (live_repo / "u.txt").read_text() == "untracked"
    for rel in _LIVE_FILES:
        assert (live_repo / rel).read_text() == "live " + rel
    assert not list((tmp_path / "bk").glob("*.tmp*"))


def test_backup_from_a_subdirectory_covers_the_whole_repo(live_repo, tmp_path):
    sub = live_repo / "src" / "deep"
    sub.mkdir(parents=True)
    (sub / "tracked.py").write_text("x")
    git(live_repo, "add", "src/deep/tracked.py")
    git(live_repo, "commit", "-qm", "sub")
    p = run_hook("git reset --hard", sub, tmp_path)
    assert p.returncode == 0 and stash_count(live_repo) == 1, p.stderr
    shown = subprocess.run(["git", "-C", str(live_repo), "show", "stash@{0}:f"], capture_output=True, text=True)
    assert shown.stdout == "2"
    with tarfile.open(_tars(tmp_path)[0]) as tf:
        assert "u.txt" in tf.getnames()


def test_cd_in_the_command_selects_the_target_repo(live_repo, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    p = run_hook(f"cd {live_repo} && git reset --hard", elsewhere, tmp_path)
    assert p.returncode == 0 and stash_count(live_repo) == 1, p.stderr


def test_only_tracked_means_no_tar_and_only_untracked_means_no_stash(tmp_path):
    repo = init_repo(tmp_path / "r")
    (repo / "f").write_text("1")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    (repo / "f").write_text("2")
    p = run_hook("git reset --hard", repo, tmp_path)
    assert p.returncode == 0 and stash_count(repo) == 1 and _tars(tmp_path) == [], p.stderr
    git(repo, "stash", "drop")
    (repo / "f").write_text("1")
    (repo / "state").mkdir()
    (repo / "state/pending.json").write_text("live")
    p = run_hook("git clean -fd", repo, tmp_path)
    assert p.returncode == 0 and stash_count(repo) == 0 and len(_tars(tmp_path)) == 1, p.stderr
    assert (repo / "state/pending.json").read_text() == "live"


def test_untracked_over_the_cap_fails_closed(live_repo, tmp_path):
    p = run_hook("git clean -fd", live_repo, tmp_path, config={"backup_untracked_cap_mb": 0})
    assert p.returncode == 2 and "backup cap" in p.stderr
    assert "back up manually or commit first" in p.stderr
    assert (live_repo / "u.txt").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read mode-000 files")
def test_unreadable_untracked_file_blocks_and_is_not_lost(live_repo, tmp_path):
    secret = live_repo / "state/secret.json"
    secret.write_text("precious")
    secret.chmod(0)
    try:
        p = run_hook("git clean -fd", live_repo, tmp_path)
        assert p.returncode == 2, p.stderr
        assert "secret.json" in p.stderr
        assert _tars(tmp_path) == []
        assert not list((tmp_path / "bk").glob(".*"))   # no leftover tmp file
    finally:
        secret.chmod(0o600)
    assert secret.read_text() == "precious"


def test_concurrent_backups_of_different_repos_get_distinct_archives(tmp_path):
    repos = []
    for k in range(2):
        repo = init_repo(tmp_path / f"r{k}")
        (repo / "f").write_text("1")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "init")
        (repo / "f").write_text("2")
        (repo / f"only-{k}.txt").write_text(f"content {k}")
        repos.append(repo)
    env = hook_env(tmp_path)
    procs = [subprocess.Popen([sys.executable, str(GUARD_PATH)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, env=env) for _ in repos]
    outs = [pr.communicate(json.dumps({"tool_input": {"command": "git clean -fd"}, "cwd": str(repo)}), timeout=60)
            for pr, repo in zip(procs, repos)]
    assert [pr.returncode for pr in procs] == [0, 0], outs
    tars = _tars(tmp_path)
    assert len(tars) == 2 and tars[0] != tars[1]
    contents = []
    for t in tars:
        with tarfile.open(t) as tf:
            contents.append(tuple(tf.getnames()))
    assert sorted(contents) == [("only-0.txt",), ("only-1.txt",)]


def test_same_label_twice_never_overwrites_a_backup(live_repo, tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_GUARDRAIL_BACKUP_DIR", str(tmp_path / "bk"))
    first = sg.backup_local(str(live_repo), "guardrail-fixed")
    before = Path(first["untracked_tar"]).read_bytes()
    with pytest.raises(sg.BackupError):
        sg.backup_local(str(live_repo), "guardrail-fixed")
    assert Path(first["untracked_tar"]).read_bytes() == before


def test_label_is_unique_per_call_and_events_are_logged(live_repo, tmp_path):
    for _ in range(2):
        run_hook("git clean -fd", live_repo, tmp_path)
    log = [json.loads(ln) for ln in (tmp_path / "events.jsonl").read_text().splitlines()]
    labels = [e["label"] for e in log if e.get("mode") == "auto_backup_local"]
    assert len(labels) == 2 and len(set(labels)) == 2
    assert all(len(lbl.split("-")) == 4 for lbl in labels)   # guardrail-<epoch>-<pid>-<uuid8>


def test_30mb_untracked_set_backs_up_quickly(live_repo, tmp_path):
    if os.getloadavg()[0] > (os.cpu_count() or 1):
        pytest.skip("machine is loaded; timing is meaningless")
    big = live_repo / "big"
    big.mkdir()
    for k in range(30):
        (big / f"f{k}.bin").write_bytes(os.urandom(1024 * 1024))
    t = time.time()
    p = run_hook("git clean -fd", live_repo, tmp_path)
    assert p.returncode == 0, p.stderr
    assert time.time() - t < 8.0, time.time() - t


def test_git_dash_c_selects_the_target_repo(live_repo, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for cmd in (f"git -C {live_repo} reset --hard", f"git -C {live_repo} clean -fd",
                f"git -C {live_repo} checkout -f work", f"git --no-pager -C {live_repo} reset --hard"):
        p = run_hook(cmd, elsewhere, tmp_path)
        assert p.returncode == 0, p.stderr
        assert "backed up tracked changes" in p.stderr, (cmd, p.stderr)
    assert stash_count(live_repo) == 4


def test_relative_and_chained_dash_c_resolve_against_cwd(live_repo, tmp_path):
    p = run_hook(f"git -C {live_repo.parent} -C {live_repo.name} reset --hard", tmp_path / "bk-none", tmp_path)
    assert p.returncode == 0 and stash_count(live_repo) == 1, p.stderr
    p = run_hook(f"git -C {live_repo.name} reset --hard", live_repo.parent, tmp_path)
    assert p.returncode == 0 and stash_count(live_repo) == 2, p.stderr


def test_each_repo_in_one_command_is_backed_up(live_repo, tmp_path):
    other = init_repo(tmp_path / "other")
    (other / "g").write_text("1")
    git(other, "add", "g")
    git(other, "commit", "-qm", "init")
    git(other, "switch", "-qc", "work")
    (other / "g").write_text("2")
    p = run_hook(f"git -C {live_repo} reset --hard && git -C {other} reset --hard", tmp_path, tmp_path)
    assert p.returncode == 0, p.stderr
    assert stash_count(live_repo) == 1 and stash_count(other) == 1


def test_unknown_target_repo_fails_closed(live_repo, tmp_path):
    for cmd in ('git -C "dir with spaces" reset --hard', 'cd "$REPO" && git reset --hard'):
        p = run_hook(cmd, live_repo, tmp_path)
        assert p.returncode == 2 and "cannot be determined" in p.stderr, (cmd, p.stderr)
    assert stash_count(live_repo) == 0


def test_git_dir_option_fails_closed(live_repo, tmp_path):
    p = run_hook(f"git --git-dir={live_repo}/.git --work-tree={live_repo} reset --hard", tmp_path, tmp_path)
    assert p.returncode == 2 and "--git-dir" in p.stderr
