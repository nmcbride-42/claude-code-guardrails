"""Hard blocks: unrecoverable commands never run.

Dangerous strings are assembled at runtime so this file never contains a
literal that an installed copy of the guard would flag while it is edited."""
import pytest

from conftest import sg

_RF = "-" + "rf"
_FR = "-" + "fr"
_RMROOT = "rm " + _RF + " /"
_DEV = "of=" + "/dev/"


@pytest.mark.parametrize("cmd,blocked", [
    ("rm " + _RF + " /", True),
    ("rm " + _FR + " /", True),                       # flag order
    ("rm -r -f /", True),                             # separated flags
    ("rm -f -r /etc", True),
    ("rm --recursive /home", True),                   # long flag
    ("rm -Rf /var", True),                            # capital R
    ("rm " + _RF + " ~", True),                       # home, all spellings
    ("rm " + _RF + " $HOME", True),
    ('rm ' + _RF + ' "${HOME}"', True),
    ("rm " + _RF + " ~/.ssh", True),                  # default irreplaceable path
    ("rm " + _RF + " /tmp/foo", False),               # ordinary scratch path
    ("rm " + _RF + " ./build", False),
    ("rm notes.txt", False),                          # not recursive
    ("/bin/rm " + _RF + " /", True),                  # binary called by absolute path
    ("/usr/bin/rm " + _RF + " ~", True),
    ("sudo /bin/rm -r /etc", True),
    ("rm " + _RF + " ~/*", True),                     # contents of home
    ("rm " + _RF + " $HOME/*", True),
    ("rm " + _RF + " ~/.*", True),
    ("rm " + _RF + " /home/*", True),
    ("rm " + _RF + " /*", True),
    ("rm " + _RF + " ~/.ssh/*", True),                # contents of an irreplaceable path
    ("rm " + _RF + " ./build/*", False),              # contents of an ordinary dir
    ("rm " + _RF + " /tmp/scratch/*", False),
])
def test_rm_normalization(cmd, blocked):
    assert sg.is_dangerous_rm(cmd)[0] is blocked
    assert sg.check_hard_block(cmd)[0] is blocked


def test_irreplaceable_ancestor_is_blocked(tmp_path, monkeypatch):
    data = tmp_path / "proj" / "data"
    data.mkdir(parents=True)
    sg.set_config({"irreplaceable_paths": [str(data)]})
    assert sg.is_dangerous_rm("rm " + _RF + " " + str(data))[0]
    assert sg.is_dangerous_rm("rm " + _RF + " " + str(tmp_path / "proj"))[0]   # ancestor
    monkeypatch.chdir(tmp_path)
    assert sg.is_dangerous_rm("rm " + _RF + " proj")[0]                        # relative ancestor
    assert not sg.is_dangerous_rm("rm " + _RF + " " + str(data / "cache"))[0]  # subpath is fine


def test_protected_repo_paths_are_exact_roots():
    sg.set_config({"protected_repos": [
        {"name": "my-app", "paths": ["/work/my-app", "~/code/my-app", "C:/w", "relative/x"]}]})
    roots = sg.protected_roots()
    assert roots["/work/my-app"] == "protected repo 'my-app'"
    assert any(k.endswith("/code/my-app") and k.startswith("/") for k in roots)
    assert "C:/w" not in roots and "relative/x" not in roots
    blocked, reason = sg.is_dangerous_rm("rm " + _RF + " /work/my-app/")
    assert blocked and "my-app" in reason
    assert not sg.is_dangerous_rm("rm " + _RF + " /work/my-app/build")[0]


@pytest.mark.parametrize("cmd,blocked", [
    ("find / -name x -delete", True),
    ("find ~ -delete", True),
    ("find /etc -type f -delete", True),
    ("find ./build -name '*.o' -delete", False),
    ("find / -name x -print", False),
    ("/usr/bin/find / -name x -delete", True),       # binary called by absolute path
    ("/usr/bin/find ./build -delete", False),
])
def test_find_delete(cmd, blocked):
    assert sg.check_hard_block(cmd)[0] is blocked


@pytest.mark.parametrize("cmd,blocked", [
    ("sudo reboot", True),
    ("shutdown -h now", True),
    ("FOO=1 nohup poweroff", True),
    ("mkfs.ext4 /dev/sdb1", True),
    ("cat /var/run/reboot-required", False),
    ("grep -n reboot foo.py", False),
    ("man mkfs", False),
    ("echo x >> /etc/ssh/sshd_config", True),
    ("sudo sed -i 's/a/b/' /etc/ssh/sshd_config", True),
    ("sudo grep PasswordAuthentication /etc/ssh/sshd_config", False),
    ("dd if=/dev/zero " + _DEV + "sda", True),
    ("echo pw | sudo -S true", True),
    ("terraform plan", False),
])
def test_command_position_and_write_intent(cmd, blocked):
    assert sg.check_hard_block(cmd)[0] is blocked


@pytest.mark.parametrize("cmd", [
    "bash -c '" + _RMROOT + "'",
    "sh -c \"" + _RMROOT + "\"",
    "eval " + _RMROOT,
    "bash -c \"bash -c '" + _RMROOT + "'\"",
])
def test_wrapped_commands_are_unwrapped(cmd):
    assert sg.check_hard_block(cmd)[0]


_P = "pu" + "sh"


@pytest.mark.parametrize("cmd,blocked", [
    (f"git {_P} origin +main:main", True),
    (f"git {_P} origin +main", True),
    (f"git {_P} origin +feature:main", True),         # force via a different source
    (f"git {_P} -f origin main", True),
    (f"git {_P} --force origin master", True),
    (f"git -C /repo {_P} --force origin main", True),  # global options before the subcommand
    (f"git {_P} origin HEAD:refs/heads/main", True),  # plain push to a protected branch
    (f"git {_P} origin main", True),
    (f"git {_P} origin +feature:feature", False),     # force, but not protected
    (f"git {_P} -u origin feature/main-menu", False),  # 'main' inside a name is not 'main'
    (f"git {_P} origin feature && git merge --ff-only x", False),
])
def test_protected_push(cmd, blocked):
    assert sg.is_protected_push_to_main(cmd)[0] is blocked


@pytest.mark.parametrize("args,implicit,dests,all_refs", [
    ([], True, [], False),                              # git push
    (["origin"], True, [], False),                      # git push origin
    (["--follow-tags", "origin"], True, [], False),
    (["-o", "ci.skip", "origin"], True, [], False),     # option value is not the remote
    (["origin", "HEAD"], False, ["HEAD"], False),
    (["--all", "origin"], False, [], True),
    (["--tags", "origin"], False, [], False),
    (["origin", "topic:main"], False, ["main"], False),
])
def test_parse_push(args, implicit, dests, all_refs):
    p = sg.parse_push(args)
    assert (p["implicit"], p["dests"], p["all"]) == (implicit, dests, all_refs)


def test_push_mirror_is_blocked_statically():
    assert sg.is_protected_push_to_main(f"git {_P} --mirror origin")[0]


def test_protected_branches_are_configurable():
    sg.set_config({"protected_branches": ["release"]})
    assert sg.is_protected_push_to_main(f"git {_P} origin release")[0]
    assert not sg.is_protected_push_to_main(f"git {_P} origin main")[0]


@pytest.mark.parametrize("cmd,blocked", [
    # commit prose describing dangerous ops: must NOT block
    ('git commit -m "guardrail: block git ' + _P + ' +main:main force-push"', False),
    ('git commit -m "cleanup: removed ' + _RMROOT + ' from the script"', False),
    ("git commit -m 'fix: handle " + _RMROOT + " safely'", False),
    ("git commit -qm 'fix: handle " + _RMROOT + " safely'", False),   # flag cluster
    ("git -C /repo commit -am 'fix: " + _RMROOT + "'", False),         # global options
    ("git commit -am 'ok' && " + _RMROOT, True),
    # real chained destruction after a commit: MUST still block
    ('git commit -m "ok" && ' + _RMROOT, True),
    ('git commit -m "ok"; ' + _RMROOT, True),
    (_RMROOT, True),
])
def test_commit_message_neutralization(cmd, blocked):
    scanned = sg.neutralize_commit_messages(cmd)
    assert sg.check_hard_block(scanned)[0] is blocked, f"cmd={cmd!r} scanned={scanned!r}"


def _scan_like_main(command):
    scan_command = sg.neutralize_commit_messages(command)
    lines = [ln for ln in scan_command.splitlines() if ln.strip()]
    return any(sg.check_hard_block(ln)[0] for ln in [scan_command] + lines)


def test_multiline_commit_message_not_blocked():
    cmd = ('git add x && git commit -q -m "guardrail: fix\n\n'
           "real chained 'git commit -m ok && " + _RMROOT + "' still blocks.\n"
           'removed ' + _RMROOT + ' from script"')
    assert _scan_like_main(cmd) is False


def test_multiline_real_chained_destruction_still_blocks():
    assert _scan_like_main("cd /repo\nrm " + _RF + " /etc") is True


def test_cwd_fallback_target_resolution():
    assert sg.extract_target_path("git reset --hard") is None
    assert sg.extract_target_path("cd /repo && git reset --hard") == "/repo"
