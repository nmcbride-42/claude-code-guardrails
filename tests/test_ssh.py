"""ssh handling: the remote command is checked with the same rules, a local
suffix after the quoted remote command is checked as a local command, and any
ambiguity about where the remote command ends fails closed.

End-to-end cases run the hook as a subprocess with a fake `ssh` on PATH that
records every call, so no real host is ever contacted."""
import resource
import time

import pytest

from conftest import GUARD_PATH, run_hook, sg, stash_count

_P = "pu" + "sh"
_RH = "--" + "hard"
_REMOTE_RESET = "cd /work/app && git reset " + _RH

STASH = {"remote": {"mode": "stash"}}  # opt-in mode; the default is "block"


@pytest.mark.parametrize("cmd,inner", [
    (f"ssh devbox 'git -C /x {_P} --force origin main' 2>&1 | tail -1", f"git -C /x {_P} --force origin main"),
    (f"ssh -o ConnectTimeout=8 devbox 'git {_P} origin HEAD:main'; echo done", f"git {_P} origin HEAD:main"),
    ("ssh devbox \"cd /x && git status\" | head -5", "cd /x && git status"),
    ("ssh devbox 'df -h /'", "df -h /"),
    ("ssh -p 2222 user@devbox uptime", "uptime"),
])
def test_parse_ssh_ignores_local_suffix(cmd, inner):
    assert sg.parse_ssh(cmd)[1] == inner


@pytest.mark.parametrize("cmd,blocked", [
    (f"ssh devbox 'git -C /x {_P} --force origin main' 2>&1 | tail -1", True),
    (f"ssh devbox 'cd /x && git {_P} origin HEAD:main'; echo done", True),
    (f"ssh devbox 'git -C /x {_P} --force-with-lease origin topic/x' 2>&1 | tail -1", False),
    (f"ssh devbox 'cd /x && git {_P} -u origin topic/y' 2>&1", False),
])
def test_ssh_wrapped_protected_push_with_suffix(cmd, blocked):
    _, inner = sg.parse_ssh(cmd)
    assert sg.is_protected_push_to_main(inner)[0] is blocked


@pytest.mark.parametrize("cmd,suffix", [
    (f"ssh devbox 'true' && git reset {_RH}", f"git reset {_RH}"),
    ("ssh devbox 'x' 2>&1 | tail -1", "2>&1 | tail -1"),
    ("ssh devbox 'x'", ""),
    ("ssh devbox git status", ""),   # unquoted: the whole remainder is the remote command
])
def test_ssh_local_suffix(cmd, suffix):
    assert sg.ssh_local_suffix(cmd) == suffix


@pytest.mark.parametrize("cmd,inner,suffix", [
    (f"ssh devbox 'true'&&bash -c 'git {_P} origin HEAD:main'", "true", f"bash -c 'git {_P} origin HEAD:main'"),
    (f"ssh devbox 'true' && ssh nas 'true' && git reset {_RH}", "true", f"ssh nas 'true' && git reset {_RH}"),
    ('ssh devbox "a \\"b\\" c" | tail', 'a "b" c', "tail"),
])
def test_first_word_scanner(cmd, inner, suffix):
    assert sg.parse_ssh(cmd)[1] == inner
    assert sg.ssh_local_suffix(cmd) == suffix


@pytest.mark.parametrize("cmd,found", [
    ("ssh devbox 'true' 2>&1 && ssh nas 'x'", ["ssh nas 'x'"]),
    ("echo hi; ssh nas 'x' || ssh box 'y'", ["ssh nas 'x' || ssh box 'y'", "ssh box 'y'"]),
    ("git status", []),
    ("echo sshfoo ssh_x", []),
])
def test_embedded_ssh_invocations(cmd, found):
    got = sg.embedded_ssh_lines(cmd)
    for f in found:
        assert f in got
    if not found:
        assert got == []


# Chains and glued quoting that once let a remote destructive op through without
# the remote status check. With an unreachable remote every one must block.
_CHAIN_CASES = [
    f"ssh devbox 'true' 2>&1 && ssh nas '{_REMOTE_RESET}'",
    f"ssh devbox 'true' >/dev/null 2>&1 && ssh nas '{_REMOTE_RESET}'",
    f"ssh devbox 'true' 2>/dev/null; ssh nas '{_REMOTE_RESET}'",
    f"ssh devbox 'true' </dev/null || ssh nas '{_REMOTE_RESET}'",
    f"ssh devbox 'true' ; ssh nas '{_REMOTE_RESET}'",
    f"ssh devbox 'true' | cat && ssh nas '{_REMOTE_RESET}'",
    f"ssh devbox 'true' 2>&1 && echo hi && ssh nas '{_REMOTE_RESET}'",
]
_UNCERTAIN_BOUNDARY = [
    f"ssh devbox 'cd /work/app && echo '\"ok\"' && git reset {_RH}'",
    f"ssh devbox \"cd /work/app && echo \"'ok'\" && git reset {_RH}\"",
    f"ssh devbox 'cd /work/app && echo 'ok' && git reset {_RH}'",
    f"ssh devbox 'cd /work/app && git reset {_RH}'foo",
    f"ssh devbox 'cd /work/app && git reset {_RH}'$X",
    f"ssh devbox 'cd /work/app && git reset {_RH}",   # unbalanced quote
    f"ssh devbox 'true' 2>&1 && ssh nas 'cd /work/app && git reset {_RH}",
]
_QUOTED_DATA = [
    f"printf '%s\\n' \"ssh devbox 'cd /work/app && git reset {_RH}'\"",
    f"echo \"ssh devbox 'cd /x && git reset {_RH}'\"",
]


@pytest.mark.parametrize("cmd", _CHAIN_CASES + _UNCERTAIN_BOUNDARY)
def test_remote_destructive_chain_blocked_when_remote_unverifiable(cmd, dirty_repo, tmp_path, fake_ssh):
    bindir, _ = fake_ssh(ok=False)
    assert run_hook(cmd, dirty_repo, tmp_path, extra_path=bindir, config=STASH).returncode == 2


@pytest.mark.parametrize("ssh_ok", [False, True])
@pytest.mark.parametrize("cmd", _QUOTED_DATA + _UNCERTAIN_BOUNDARY)
def test_quoted_data_and_uncertain_boundary_issue_no_side_effects(cmd, ssh_ok, dirty_repo, tmp_path, fake_ssh):
    bindir, trace = fake_ssh(ok=ssh_ok)
    p = run_hook(cmd, dirty_repo, tmp_path, extra_path=bindir, config=STASH)
    assert p.returncode == 2
    if cmd in _QUOTED_DATA:
        assert trace.read_text() == ""
    assert stash_count(dirty_repo) == 0


@pytest.mark.parametrize("cmd", [
    f"ssh devbox 'true' && git reset {_RH}",
    "ssh devbox 'true' ; git checkout -f main",
    f"git reset {_RH} && ssh devbox true",
])
def test_ssh_plus_local_destructive_blocks_without_side_effects(cmd, dirty_repo, tmp_path, fake_ssh):
    bindir, trace = fake_ssh(ok=True)
    p = run_hook(cmd, dirty_repo, tmp_path, extra_path=bindir, config=STASH)
    assert p.returncode == 2 and stash_count(dirty_repo) == 0 and trace.read_text() == ""


def test_clean_remote_reset_is_allowed_after_a_remote_check(dirty_repo, tmp_path, fake_ssh):
    bindir, trace = fake_ssh(ok=True)
    p = run_hook(f"ssh devbox '{_REMOTE_RESET}' 2>&1 | tail -1", dirty_repo, tmp_path, extra_path=bindir, config=STASH)
    assert p.returncode == 0 and stash_count(dirty_repo) == 0
    assert "git status --porcelain" in trace.read_text()


def test_remote_reset_without_cd_is_blocked(dirty_repo, tmp_path, fake_ssh):
    bindir, trace = fake_ssh(ok=True)
    p = run_hook(f"ssh devbox 'git reset {_RH}'", dirty_repo, tmp_path, extra_path=bindir, config=STASH)
    assert p.returncode == 2 and "target repo is unknown" in p.stderr and trace.read_text() == ""


def test_remote_block_mode_never_opens_ssh(dirty_repo, tmp_path, fake_ssh):
    bindir, trace = fake_ssh(ok=True)
    p = run_hook(f"ssh devbox '{_REMOTE_RESET}'", dirty_repo, tmp_path, extra_path=bindir,
                 config={"remote": {"mode": "block"}})
    assert p.returncode == 2 and "blocked by configuration" in p.stderr and trace.read_text() == ""
    # non-destructive remote commands are unaffected
    assert run_hook("ssh devbox 'git status'", dirty_repo, tmp_path, extra_path=bindir,
                    config={"remote": {"mode": "block"}}).returncode == 0


def test_remote_allowed_hosts(dirty_repo, tmp_path, fake_ssh):
    bindir, trace = fake_ssh(ok=True)
    cfg = {"remote": {"mode": "stash", "allowed_hosts": ["devbox"]}}
    assert run_hook(f"ssh devbox '{_REMOTE_RESET}'", dirty_repo, tmp_path, extra_path=bindir,
                    config=cfg).returncode == 0
    p = run_hook(f"ssh nas '{_REMOTE_RESET}'", dirty_repo, tmp_path, extra_path=bindir, config=cfg)
    assert p.returncode == 2 and "nas" not in trace.read_text()


# ---------------------------------------------------------------- resource bounds

def _limited():
    resource.setrlimit(resource.RLIMIT_AS, (256 * 2**20, 256 * 2**20))


def _timed_hook(cmd, cwd, tmp_path):
    t = time.time()
    p = run_hook(cmd, cwd, tmp_path, preexec_fn=_limited)
    return p.returncode, time.time() - t, p.stderr


@pytest.mark.parametrize("n", [800, 5000])
def test_many_quoted_ssh_args_fast_bounded_and_blocked(n, dirty_repo, tmp_path):
    cmd = "printf '%s\\n' " + " ".join(["'ssh devbox true'"] * n)
    rc, secs, err = _timed_hook(cmd, dirty_repo, tmp_path)
    assert rc == 2 and "too many ssh" in err and "MemoryError" not in err
    assert secs < 2.0, secs
    t = time.time()
    offs = [m.start() for m in sg._SSH_WORD_RE.finditer(cmd)]
    assert len(offs) == n and time.time() - t < 1.0


def test_100kb_single_line_fast(dirty_repo, tmp_path):
    for cmd in ["echo " + "x" * 100_000, "ssh devbox '" + "x " * 50_000 + "'", "ssh devbox " + "'a'" * 30_000]:
        rc, secs, err = _timed_hook(cmd, dirty_repo, tmp_path)
        assert rc in (0, 2) and "MemoryError" not in err and "internal error" not in err
        assert secs < 5.0, (cmd[:20], secs)


def test_ssh_occurrences_exactly_at_cap_scanned_normally(dirty_repo, tmp_path):
    cmd = "echo " + " ".join(["ssh"] * 32) + " x"
    assert len(list(sg._SSH_WORD_RE.finditer(cmd))) == sg.MAX_SSH_OCCURRENCES
    rc, _, err = _timed_hook(cmd, dirty_repo, tmp_path)
    assert rc == 0 and err == ""
    rc, _, err = _timed_hook(cmd + " ssh x", dirty_repo, tmp_path)   # 33 -> blocked
    assert rc == 2 and "too many ssh" in err


def test_32_quoted_ssh_plus_one_100kb_arg_blocked_fast(dirty_repo, tmp_path):
    cmd = "printf '%s\\n' " + " ".join(["'ssh devbox true'"] * 32) + " '" + "x" * 100_000 + "'"
    rc, secs, err = _timed_hook(cmd, dirty_repo, tmp_path)
    assert rc == 2 and "too large to verify" in err and "MemoryError" not in err
    assert secs < 3.0, secs


def test_32_occurrences_with_small_tail_under_budget_completes(dirty_repo, tmp_path):
    cmd = "printf '%s\\n' " + " ".join(["'ssh devbox true'"] * 31) + " 'ssh' '" + "x" * 2_000 + "'"
    rc, secs, err = _timed_hook(cmd, dirty_repo, tmp_path)
    assert rc == 0 and secs < 5.0, (rc, secs, err)


def test_scan_deadline_blocks(dirty_repo, tmp_path, fake_ssh):
    src = tmp_path / "g.py"
    text = GUARD_PATH.read_text()
    assert "EXTRA_SCAN_DEADLINE_S = 3.0" in text
    src.write_text(text.replace("EXTRA_SCAN_DEADLINE_S = 3.0", "EXTRA_SCAN_DEADLINE_S = -1.0"))
    bindir, trace = fake_ssh(ok=True)
    p = run_hook("echo hi; ssh devbox 'df -h'", dirty_repo, tmp_path, extra_path=bindir, src=src)
    assert p.returncode == 2 and trace.read_text() == "" and stash_count(dirty_repo) == 0


def test_default_remote_mode_blocks_without_ssh(dirty_repo, tmp_path, fake_ssh):
    bindir, trace = fake_ssh(ok=True)
    p = run_hook(f"ssh devbox '{_REMOTE_RESET}'", dirty_repo, tmp_path, extra_path=bindir)
    assert p.returncode == 2 and "blocked by configuration" in p.stderr
    assert trace.read_text() == ""
