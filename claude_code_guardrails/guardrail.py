#!/usr/bin/env python3
"""
claude-code-guardrails: a PreToolUse safety hook for Claude Code's Bash tool.

Two modes of action:
  HARD_BLOCK   exit 2, the command never runs (unrecoverable operations).
  AUTO_BACKUP  when a recoverable-but-destructive git op is about to run on a
               dirty tree, back the tree up first (without touching it), then
               exit 0 and let the command run.

SSH-aware: parses `ssh <host> "<inner>"` and applies the same rules to the
inner command. Depending on configuration it either checks the remote tree and
stashes it there before a destructive op, or blocks destructive remote ops.

Protocol: reads the hook JSON from stdin ({"tool_input": {"command": ...},
"cwd": ...}), writes block messages to stderr, exits 2 to block. Malformed
payloads fail open (exit 0); an internal error fails closed (exit 2).

Standard library only. The file can be run directly as a script.
"""
import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

__all__ = ["main", "check_hard_block", "needs_stash", "load_config", "set_config"]

# --------------------------------------------------------------------------- configuration

CONFIG_ENV = "CLAUDE_GUARDRAIL_CONFIG"
LOG_ENV = "CLAUDE_GUARDRAIL_LOG"
BACKUP_DIR_ENV = "CLAUDE_GUARDRAIL_BACKUP_DIR"

DEFAULT_CONFIG_PATH = Path("~/.config/claude-code-guardrails/config.json")
DEFAULT_STATE_DIR = Path("~/.cache/claude-code-guardrails")

DEFAULT_CONFIG = {
    # A push (forced or not) that names one of these as its destination is
    # blocked, as is a local push whose implicit destination (current branch,
    # upstream, push target, --all) is one of them, and so is `git commit`
    # while one of these is checked out.
    "protected_branches": ["main", "master"],
    "block_commit_on_protected_branch": True,
    # Repos whose checkout directories must never be recursively deleted.
    # [{"name": "my-app", "paths": ["~/code/my-app", "/srv/my-app"]}]
    "protected_repos": [],
    # Extra directories that are catastrophic to delete AS THEMSELVES
    # (subpaths stay deletable).
    "protected_paths": [],
    # Directories that cannot be recovered from git: deleting one of them OR
    # ANY ANCESTOR (e.g. `rm -rf ~` or `rm -rf data/..`) is blocked.
    "irreplaceable_paths": ["~/.claude", "~/.ssh", "~/.gnupg"],
    # How to treat destructive git ops wrapped in `ssh <host> '...'`
    # (default "block": the safe choice when you haven't vetted the remote):
    #   "stash": check the remote tree over ssh (BatchMode) and `git stash push -u`
    #            it there if dirty; block if the remote cannot be verified.
    #   "block": block every destructive git op sent over ssh; the hook never
    #            opens an ssh connection itself.
    # allowed_hosts (stash mode only): if non-empty, hosts not listed are
    # treated as "block".
    "remote": {"mode": "block", "allowed_hosts": []},
    # Untracked files larger than this (total) are not archived: the hook
    # blocks instead, so you can back them up yourself.
    "backup_untracked_cap_mb": 32,
}

_CONFIG = None


class ConfigError(Exception):
    pass


def _merge(base, override):
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path=None):
    """Load the config file (env CLAUDE_GUARDRAIL_CONFIG, else
    ~/.config/claude-code-guardrails/config.json) merged over the defaults.
    A missing file means defaults. An unreadable or invalid file raises
    ConfigError: the hook then fails closed rather than silently dropping the
    protections you configured."""
    explicit = path or os.environ.get(CONFIG_ENV)
    p = Path(explicit).expanduser() if explicit else DEFAULT_CONFIG_PATH.expanduser()
    if not p.exists():
        if explicit:
            raise ConfigError(f"config file {p} (from {CONFIG_ENV}) does not exist")
        return _merge(DEFAULT_CONFIG, {})
    try:
        data = json.loads(p.read_text())
    except Exception as e:
        raise ConfigError(f"cannot parse config {p}: {e}")
    if not isinstance(data, dict):
        raise ConfigError(f"config {p} must be a JSON object")
    cfg = _merge(DEFAULT_CONFIG, {k: v for k, v in data.items() if not k.startswith("_")})
    for key in ("protected_branches", "protected_repos", "protected_paths", "irreplaceable_paths"):
        if not isinstance(cfg[key], list):
            raise ConfigError(f"config key {key!r} must be a list")
    if cfg["remote"].get("mode") not in ("stash", "block"):
        raise ConfigError("config remote.mode must be 'stash' or 'block'")
    return cfg


def set_config(cfg):
    """Install a config dict (merged over the defaults). Used by tests and by
    callers that embed the guard."""
    global _CONFIG
    _CONFIG = _merge(DEFAULT_CONFIG, cfg or {})


def get_config():
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_config()
    return _CONFIG


def _home():
    return str(Path.home())


def _expand(p):
    return os.path.normpath(os.path.expanduser(p)) if p else p


def _state_dir():
    return DEFAULT_STATE_DIR.expanduser()


def log_event(event_type, details):
    """Append one JSON line to the event log. Set CLAUDE_GUARDRAIL_LOG=none to
    disable. Logging never blocks the hook."""
    target = os.environ.get(LOG_ENV)
    if target and target.lower() in ("none", "off", "0"):
        return
    try:
        path = Path(target).expanduser() if target else _state_dir() / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "type": event_type,
            "ts_epoch": int(time.time()),
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            **details,
        }
        with path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------- patterns

HARD_BLOCK_PATTERNS = [
    # Plain `rm`, root and system-dir cases live in is_dangerous_rm() (tokenized,
    # flag-order independent, home-aware); mkfs, shutdown/reboot and sshd_config
    # have command-position / write-intent checks below so that reading or
    # grepping for those words does not false-block.
    (re.compile(r"\bchmod\s+(-R\s+)?777\s+/(\s|$)"), "chmod 777 on root"),
    (re.compile(r"\bdd\s+.*of=/dev/"), "dd writing to device"),
    (re.compile(r"\bDROP\s+(TABLE|DATABASE)\b", re.I), "SQL DROP"),
    (re.compile(r":\(\)\s*\{"), "fork bomb"),
    (re.compile(r"\bkill\s+-9\s+1\b"), "kill PID 1"),
    # `\brm\b`, not bare `rm`, so "terraform" does not match the "rm" in "form".
    (re.compile(r"(\brm\b|>>?)\s*.*authorized_keys\b"), "authorized_keys modification"),
    # sudo hardening: password brute-force via stdin and askpass hijack.
    (re.compile(r"\bsudo\s+(?:-[A-Za-z]+\s+)*-S\b"), "sudo -S (stdin-fed password)"),
    (re.compile(r"\bsudo\s+(?:-[A-Za-z]+\s+)*-A\b"), "sudo -A (askpass-helper hijack)"),
    (re.compile(r"SUDO_ASKPASS\s*=\s*\S+\s+sudo\b"), "SUDO_ASKPASS environment override"),
    (re.compile(r"echo\s+.+\|\s*sudo\s+(?:-[A-Za-z]+\s+)*-S\b"), "echo-piped sudo (password brute-force)"),
]

# `_GIT` (defined with the git-invocation helpers below) is `git` plus any
# global options, so `git -C <repo> reset --hard` matches like `git reset --hard`.
def _auto_stash_patterns():
    g = _GIT
    return [
        (re.compile(g + r"checkout\s+(-f|--force)\b"), "git checkout -f"),
        (re.compile(g + r"checkout\s+.*\s+-f\b"), "git checkout -f"),
        (re.compile(g + r"checkout\s+-[a-zA-Z]*[fB][a-zA-Z]*\b"), "git checkout -f/-B"),
        (re.compile(g + r"reset\s+--hard\b"), "git reset --hard"),
        (re.compile(g + r"checkout\s+(?:\S+\s+)*--(?:\s|$)"), "git checkout -- <path>"),
        (re.compile(g + r"clean\s+-[a-zA-Z]*f"), "git clean -f"),
        (re.compile(g + r"restore\s+.*\s+(--source|-s)\b"), "git restore with source"),
        (re.compile(g + r"switch\s+(-f|--force|--discard-changes)\b"), "git switch --force"),
    ]


# --------------------------------------------------------------------------- ssh parsing

_SSH_HEAD_RE = r"^\s*ssh\s+(?:-[A-Za-z]\s+\S+\s+|-[A-Za-z]\S+\s+|-o\s+\S+\s+)*(\S+)\s+(.+)$"


def parse_ssh(command):
    """Detect `ssh <host> "<inner>"` and return (host, inner_cmd) or (None, None).
    Handles: ssh host "cmd", ssh user@host 'cmd', ssh -p 22 host cmd. One level
    only (ssh a ssh b ... is not unwrapped further)."""
    m = re.match(_SSH_HEAD_RE, command.strip())
    if not m:
        return None, None
    host = m.group(1)
    rest = m.group(2).strip()
    # A quoted remote command is the FIRST shell word; anything after it (a
    # redirect, `| tail -1`, `; echo`) runs locally. Taking only that word means
    # a quoted push followed by `2>&1 | tail -1` is still seen for what it is.
    if rest[:1] in ('"', "'"):
        word, _ = _first_word(rest)
        rest = word
    return host, rest


def _first_word(text):
    """Split `text` (starting with a quote) into its first shell word, unquoted,
    and the rest of the line verbatim. Single quotes end at the next single
    quote; double quotes honour backslash escapes. Characters glued to the
    closing quote belong to the same word until whitespace or an operator
    (; & | < >). Hand-written, because shlex's punctuation_chars buffering loses
    characters in inputs like `'x'&&...`."""
    q, i, word = text[0], 1, []
    while i < len(text):
        c = text[i]
        if c == q:
            i += 1
            break
        if q == '"' and c == "\\" and i + 1 < len(text):
            word.append(text[i + 1])
            i += 2
            continue
        word.append(c)
        i += 1
    while i < len(text) and not text[i].isspace() and text[i] not in ";&|<>":
        word.append(text[i])
        i += 1
    return "".join(word), text[i:]


def ssh_local_suffix(command):
    """The part of an `ssh <host> '<quoted remote command>' <suffix>` line that
    runs LOCALLY, without its leading operator, or "" if there is none. main()
    checks it as a local command, so a chain of ssh calls cannot hide a
    destructive local command."""
    m = re.match(_SSH_HEAD_RE, command.strip())
    if not m or m.group(2).strip()[:1] not in ('"', "'"):
        return ""
    _, suffix = _first_word(m.group(2).strip())
    return re.sub(r"^\s*(?:&&|\|\||;|\||&)\s*", "", suffix).strip()


MAX_SSH_OCCURRENCES = 32
MAX_EXTRA_SCAN_BYTES = 256 * 1024
EXTRA_SCAN_DEADLINE_S = 3.0
_SSH_WORD_RE = re.compile(r"(?<![\w./-])ssh(?=\s)")
_LEAD_NOISE_RE = re.compile(r"^\s*(?:(?:\d*[<>]+&?\S*|&&|\|\||;|\||&)\s*)+")


def embedded_ssh_lines(text):
    """Every substring of `text` that starts at an `ssh` word other than position
    0. A chained or redirected line (`ssh a 'x' 2>&1 && ssh b 'y'`) hides further
    ssh calls from a first-word check; each one is scanned as a line of its own.
    Over-matching only adds checks (fail closed)."""
    return [text[m.start():] for m in _SSH_WORD_RE.finditer(text) if m.start() > 0]


def starts_with_ssh(line):
    """True if the line, after leading redirections and operators, is an ssh call."""
    return bool(re.match(r"ssh\s", _LEAD_NOISE_RE.sub("", line, count=1).lstrip()))


def ssh_boundary_uncertain(command):
    """True when we cannot be sure where the remote command of
    `ssh <host> '<quoted>' ...` ends: an unbalanced quote, or anything glued to
    the closing quote that is not whitespace/end/an operator (`'a '"b"' c'`,
    `'cmd'foo`, `'cmd'$X`). The shell concatenates adjacent pieces into ONE word,
    so the first-word split would be wrong."""
    m = re.match(_SSH_HEAD_RE, command.strip())
    if not m:
        return False
    rest = m.group(2).strip()
    if rest[:1] not in ('"', "'"):
        return False
    q, i = rest[0], 1
    while i < len(rest):
        c = rest[i]
        if q == '"' and c == "\\" and i + 1 < len(rest):
            i += 2
            continue
        if c == q:
            break
        i += 1
    else:
        return True   # never closed
    nxt = rest[i + 1:i + 2]
    return bool(nxt) and not nxt.isspace() and nxt not in ";&|<>"


def legacy_ssh(line):
    """The conservative reading of an ssh line: host, and the WHOLE remainder
    with matching outer quotes stripped. This is the only reading allowed to
    drive side effects (remote status checks, remote stash), so static shell
    parsing can never widen what the hook itself runs."""
    m = re.match(_SSH_HEAD_RE, line.strip())
    if not m:
        return None, None
    rest = m.group(2).strip()
    if len(rest) >= 2 and rest[0] in ('"', "'") and rest[-1] == rest[0]:
        rest = rest[1:-1]
    return m.group(1), rest


def ssh_block_candidates(line):
    """Readings of an ssh line that may only BLOCK (never trigger ssh/stash):
    the first-word reading, plus the conservative reading when the remote
    command boundary is uncertain."""
    out = []
    host, inner = parse_ssh(line)
    if host and inner:
        out.append((host, inner))
    if ssh_boundary_uncertain(line):
        host, inner = legacy_ssh(line)
        if host and inner and (host, inner) not in out:
            out.append((host, inner))
    return out


def ssh_mixed_with_destructive(line, needs_stash_fn):
    """True when `line` has an ssh invocation AND a destructive git op that is
    not provably confined to one clean, single remote argument. The line must
    start with ssh, have a certain boundary, carry the op inside the quoted
    remote word, and have none in the local suffix. Anything else (quoted data,
    glued segments, a local op after ssh) is blocked, not guessed at."""
    if not _SSH_WORD_RE.search(line) or not needs_stash_fn(line):
        return False
    m = re.match(_SSH_HEAD_RE, line.strip())
    if not m or ssh_boundary_uncertain(line) or m.group(2).strip()[:1] not in ("'", '"'):
        return True
    word, _ = _first_word(m.group(2).strip())
    return not needs_stash_fn(word) or bool(needs_stash_fn(ssh_local_suffix(line)))


# --------------------------------------------------------------------------- git invocations

# One option value in a regex: a quoted string (which may hold spaces) or a word.
_ARG = r"""(?:"[^"]*"|'[^']*'|\S+)"""
# `git`, then any global options, then whitespace: the subcommand comes next.
# So `git -C /repo reset --hard` and `git --no-pager -c x=y checkout -f` match
# the same rules as the bare forms.
_GIT = (r"\bgit(?:\s+(?:-[Cc]\s+" + _ARG
        + r"|--(?:git-dir|work-tree|namespace|config-env)(?:=\S+|\s+" + _ARG + r")"
        + r"|-{1,2}[A-Za-z][\w-]*(?:=\S+)?))*\s+")

# Global options that take their value as the next word.
_GIT_ARG_OPTS = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env")
# Global options that move the repository away from the working directory.
_GIT_DIR_OPTS = ("--git-dir", "--work-tree")

# A directory named in the command that cannot be known statically: an empty
# value (a quoted path with spaces after quoted-data neutralisation), `cd -`, or
# a variable other than $HOME.
UNKNOWN_DIR = object()


def _segment_tokens(seg):
    try:
        toks = shlex.split(seg)
    except ValueError:
        toks = seg.split()
    if toks and toks[0].startswith("("):   # `(cd /x; ...)`
        toks[0] = toks[0].lstrip("(")
        if not toks[0]:
            toks = toks[1:]
    return toks


def parse_git_globals(tokens):
    """For the first `git` invocation in `tokens` (matched on basename, so
    `/usr/bin/git` counts): (subcommand_index, c_dirs, dir_opts), or None.
    c_dirs are the `-C` values in order; dir_opts are `--git-dir` / `--work-tree`
    options normalised to `--opt=value`."""
    git_idx = _index_of_command(tokens, "git")
    if git_idx is None:
        return None
    c_dirs, dir_opts = [], []
    i = git_idx + 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in _GIT_ARG_OPTS:
            val = tokens[i + 1] if i + 1 < len(tokens) else ""
            if tok == "-C":
                c_dirs.append(val)
            elif tok in _GIT_DIR_OPTS:
                dir_opts.append(f"{tok}={val}")
            i += 2
            continue
        if tok.split("=", 1)[0] in _GIT_DIR_OPTS and "=" in tok:
            dir_opts.append(tok)
            i += 1
            continue
        if tok.startswith("-"):
            i += 1
            continue
        break
    return i, c_dirs, dir_opts


def _join_dir(base, path):
    """`path` resolved against `base` the way `cd` and `git -C` resolve it, or
    UNKNOWN_DIR when it cannot be known statically."""
    if base is UNKNOWN_DIR or path == "" or path == "-":
        return UNKNOWN_DIR
    path = _expand_home_token(path)
    if path.startswith("~"):
        path = os.path.expanduser(path)
    if "$" in path or path.startswith("~"):
        return UNKNOWN_DIR
    if os.path.isabs(path):
        return os.path.normpath(path)
    if not base:
        return UNKNOWN_DIR
    return os.path.normpath(os.path.join(base, path))


def git_targets(line, hook_cwd, match_fn):
    """Each git invocation in `line` that `match_fn` accepts, as
    (repo_dir, dir_opts, segment, tokens). repo_dir is where git runs: the hook's
    cwd, moved by every `cd <path>` earlier in the line, then by each
    `-C <path>`. It is UNKNOWN_DIR when a path cannot be known statically, and
    None when there is no cwd at all. ssh segments are skipped (the remote path is
    checked separately); one level of `bash -c` / `eval` is unwrapped."""
    base = hook_cwd or None
    out = []
    for seg in _split_segments(line):
        toks = _segment_tokens(seg)
        if not toks:
            continue
        head = toks[0].rsplit("/", 1)[-1]
        if head == "ssh":
            continue
        if head == "cd":
            base = _join_dir(base, toks[1] if len(toks) > 1 else "~")
            continue
        if not match_fn(seg):
            continue
        g = parse_git_globals(toks)
        if g is None:
            inner = extract_wrapped_command(seg.strip())
            if inner:
                toks = _segment_tokens(inner)
                g = parse_git_globals(toks)
        target = base
        dir_opts = []
        if g is not None:
            _, c_dirs, dir_opts = g
            for c in c_dirs:
                target = _join_dir(target, c)
        out.append((target, dir_opts, seg, toks))
    return out


def extract_target_path(cmd):
    """Working directory named in a command like `cd /path && git reset --hard`
    or `(cd /path; ...)`, or None. Used for ssh-wrapped remote commands, where
    the path is on the other host and is passed to it verbatim."""
    m = re.search(r"\bcd\s+([^\s;&|]+)", cmd)
    if m:
        return m.group(1).strip("'\"")
    return None


def _resolve(path):
    try:
        return str(Path(path).resolve())
    except Exception:
        return path


def _git_out(path, dir_opts, *args):
    """stdout of a read-only git query, or None on any failure."""
    try:
        r = subprocess.run(["git", "-C", path, *dir_opts, *args], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


# --------------------------------------------------------------------------- branch guards

_COMMIT_RE = re.compile(_GIT + r"commit\b(?!-)")   # `git commit`, not `git commit-tree`


def current_branch(path, dir_opts=()):
    """Current branch of the repo at `path`, or None (not a repo, detached HEAD).
    `symbolic-ref` rather than `rev-parse --abbrev-ref` so a freshly initialised
    repo with no commits still reports its branch."""
    return _git_out(path, list(dir_opts), "symbolic-ref", "--short", "HEAD") or None


def is_commit_on_protected_branch(cmd, hook_cwd):
    """(blocked, reason) when `git commit` would run on a protected branch.

    The target repo is the hook's cwd, moved by any `cd <path>` earlier in the
    command and by `git -C <path>` (`--git-dir` / `--work-tree` are passed
    through to the branch lookup). The branch is read BEFORE the command runs,
    so a chained `git checkout -b x && git commit` is blocked too: run the
    checkout as its own call. (Every in-chain exemption we tried could be
    bypassed.) ssh-wrapped commits are skipped; the protected-push block covers
    the remote case. A target that cannot be known statically (`cd "$REPO"`) is
    not checked."""
    if not get_config().get("block_commit_on_protected_branch", True):
        return False, None
    if not _COMMIT_RE.search(cmd):
        return False, None
    if cmd.lstrip().startswith(("ssh ", "ssh\t")):
        return False, None
    for target, dir_opts, _, _ in git_targets(cmd, hook_cwd, _COMMIT_RE.search):
        if target is None or target is UNKNOWN_DIR:
            continue
        target_path = _resolve(target)
        branch = current_branch(target_path, dir_opts)
        if branch and branch in get_config()["protected_branches"]:
            return True, (
                f"git commit on protected branch '{branch}' at {target_path}. "
                f"Create a branch first (`git -C {target_path} switch -c <topic>`) as its own "
                f"command, then commit. The branch is checked before the command runs, so "
                f"`git switch -c x && git commit` in one call is blocked too."
            )
    return False, None


def find_git_push_args(tokens):
    """Tokens after `push` in a `git ... push <args>` invocation, or None.
    Skips global git options (`-C <path>`, `-c k=v`, `--git-dir=...`) between
    `git` and the subcommand, so `git -C /repo push --force origin main` is
    recognised."""
    g = parse_git_globals(tokens)
    if g is None:
        return None
    i = g[0]
    if i < len(tokens) and tokens[i] == "push":
        return tokens[i + 1:]
    return None


# push options whose value is the next word (so it is not mistaken for the remote)
_PUSH_VALUE_OPTS = ("-o", "--push-option", "--receive-pack", "--exec", "--repo")


def parse_push(args):
    """Given the tokens after `push`: a dict with
      force     -f/--force/--force-with-lease, or a `+refspec`
      dests     destination branch of each explicit refspec (`refs/heads/`
                stripped; a bare `HEAD` or `@` is kept as is)
      all       --all / --branches (every local branch)
      mirror    --mirror (every ref, forced, remote-only refs deleted)
      implicit  no refspec and nothing that names refs: git picks the
                destination from the current branch, its upstream and config.

    The destination is the part after the last `:` (or the whole token for a
    same-name push). Only the destination branch name itself is compared to the
    protected list, never a substring of the command, so `feature/main-menu` is
    not mistaken for `main`."""
    force = all_refs = mirror = names_refs = repo_opt = False
    positional = []
    skip = False
    for t in args:
        if skip:
            skip = False
            continue
        if t in ("-f", "--force", "--force-with-lease") or t.startswith("--force-with-lease="):
            force = True
            continue
        if t in _PUSH_VALUE_OPTS:
            skip = True
            repo_opt = repo_opt or t == "--repo"
            continue
        if t.startswith("--repo="):
            repo_opt = True
            continue
        if t in ("--all", "--branches"):
            all_refs = True
            continue
        if t == "--mirror":
            mirror = force = True
            continue
        if t in ("--tags", "--follow-tags", "--delete", "-d"):
            names_refs = names_refs or t in ("--tags", "--delete", "-d")
            continue
        if t.startswith("+"):
            force = True
            positional.append(t[1:])
            continue
        if t.startswith("-"):
            continue
        positional.append(t)
    refspecs = positional if repo_opt else positional[1:]   # positional[0] is the remote
    dests = [t.split(":")[-1].removeprefix("refs/heads/") for t in refspecs]
    implicit = not dests and not all_refs and not mirror and not names_refs
    return {"force": force, "dests": dests, "all": all_refs, "mirror": mirror, "implicit": implicit}


def push_force_and_destinations(args):
    """(force, [dest_branch, ...]) for the tokens after `push`. See parse_push."""
    p = parse_push(args)
    return p["force"], p["dests"]


def _push_segments(cmd):
    for seg in re.split(r"(?:&&|\|\||;|\|)", cmd):
        if not re.search(r"\bgit\b", seg) or not re.search(r"\bpush\b", seg):
            continue
        try:
            seg_tokens = shlex.split(seg) if seg.strip() else []
        except ValueError:
            seg_tokens = seg.split()
        args = find_git_push_args(seg_tokens)
        if args is not None:
            yield args


def is_protected_push_to_main(cmd):
    """(blocked, reason) for a push, forced or plain, that NAMES a protected
    branch as its destination, and for `push --mirror` (which overwrites every
    remote branch). Each `&&`/`||`/`;`/`|` segment is checked on its own. Pushes
    whose destination git picks itself (`git push`, `git push origin`,
    `git push origin HEAD`, `--all`) need the repo's state: see
    is_implicit_push_to_protected."""
    protected = get_config()["protected_branches"]
    for args in _push_segments(cmd):
        p = parse_push(args)
        if p["mirror"] and protected:
            return True, ("push --mirror overwrites every remote branch, protected ones included. "
                          "Push named topic branches instead.")
        for dst in p["dests"]:
            if dst not in protected:
                continue
            if p["force"]:
                return True, f"force-push to protected branch '{dst}'"
            return True, (f"push to protected branch '{dst}': never push directly to a protected "
                          f"branch. Push a topic branch and merge through a pull request.")
    return False, None


def implicit_push_destinations(repo, dir_opts, push):
    """Branch names a push without an explicit destination would update in the
    repo at `repo`: for `git push` / `git push <remote>`, the current branch, its
    upstream and its @{push} branch (and every local branch under
    push.default=matching); for a bare `HEAD`/`@` refspec, the current branch;
    for --all, every local branch. Empty when the repo cannot be read."""
    dir_opts = list(dir_opts)
    names = set()
    branch = current_branch(repo, dir_opts)
    every = push["all"] or (push["implicit"]
                            and _git_out(repo, dir_opts, "config", "push.default") == "matching")
    if every:
        heads = _git_out(repo, dir_opts, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
        names.update((heads or "").split())
    if branch and any(d in ("HEAD", "@") for d in push["dests"]):
        names.add(branch)
    if branch and push["implicit"]:
        names.add(branch)
        tracked = _git_out(repo, dir_opts, "for-each-ref",
                           "--format=%(upstream:lstrip=3)%00%(push:lstrip=3)", f"refs/heads/{branch}")
        names.update(n for n in (tracked or "").split("\0") if n)
    return names


def is_implicit_push_to_protected(cmd, hook_cwd):
    """(blocked, reason) for a local push whose destination git chooses itself
    and resolves to a protected branch: `git push` or `git push origin` while a
    protected branch (or a branch tracking one) is checked out, `git push origin
    HEAD` on a protected branch, and `--all` when a protected branch exists
    locally. The repo is read before the command runs. ssh-wrapped pushes are
    not resolved (the repo is on the other host)."""
    protected = set(get_config()["protected_branches"])
    if not protected or not re.search(r"\bpush\b", cmd) or cmd.lstrip().startswith(("ssh ", "ssh\t")):
        return False, None

    def is_push(seg):
        return find_git_push_args(_segment_tokens(seg)) is not None

    for target, dir_opts, _, toks in git_targets(cmd, hook_cwd, is_push):
        if target is None or target is UNKNOWN_DIR:
            continue
        args = find_git_push_args(toks)
        if args is None:
            continue
        push = parse_push(args)
        if not (push["implicit"] or push["all"] or any(d in ("HEAD", "@") for d in push["dests"])):
            continue
        hit = sorted(implicit_push_destinations(_resolve(target), dir_opts, push) & protected)
        if hit:
            return True, (f"this push would update protected branch '{hit[0]}' (destination chosen "
                          f"by git from the current branch, its upstream or --all). Name a topic "
                          f"branch explicitly, e.g. `git push -u origin <topic>`, and merge through "
                          f"a pull request.")
    return False, None


# --------------------------------------------------------------------------- backups

def check_dirty_local(path):
    """True if the local git tree has uncommitted changes (False if clean, not a
    repo, or unknown)."""
    try:
        r = subprocess.run(["git", "-C", path, "status", "--porcelain"],
                           capture_output=True, text=True, timeout=5)
        return bool(r.stdout.strip())
    except Exception:
        return False


def check_dirty_remote(host, path):
    """True (dirty), False (clean), or None (could not verify). None makes the
    caller fail closed: treating an ssh auth failure as "clean" would let a
    destructive op run on a dirty tree nobody inspected."""
    try:
        remote_cmd = f"cd {shlex.quote(path)} && git status --porcelain"
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, remote_cmd],
                           capture_output=True, text=True, timeout=20)
        if r.returncode != 0:
            return None
        return bool(r.stdout.strip())
    except Exception:
        return None


# The local backup NEVER touches the working tree or index. An earlier design ran
# `git stash push -u` and, when a command only *mentioned* a destructive op, swept
# live uncommitted files out of a working tree that other processes were using.
# Now tracked changes are recorded with `git stash create` + `git stash store`
# (worktree and index untouched) and untracked files go to a tar.gz.

class BackupError(Exception):
    pass


def _backup_cap_bytes():
    return int(float(get_config().get("backup_untracked_cap_mb", 32)) * 1024 * 1024)


def _backup_dir():
    env = os.environ.get(BACKUP_DIR_ENV)
    d = Path(env).expanduser() if env else _state_dir() / "backups"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def backup_local(path, label):
    """Back up a dirty repo WITHOUT modifying its working tree or index.
    Returns {"stash": label or None, "untracked_tar": path or None}. Raises
    BackupError (the caller blocks, fail closed) when a backup cannot be made,
    including an untracked set over the size cap. Recover with
    `git stash apply <ref>` and `tar -xzf <tar>`."""
    import tarfile
    try:
        top = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel"], capture_output=True,
                             text=True, timeout=15, check=True).stdout.strip()
        info = {"stash": None, "untracked_tar": None}
        r = subprocess.run(["git", "-C", top, "stash", "create", label], capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise BackupError(f"git stash create failed: {r.stderr.strip()[:200]}")
        sha = r.stdout.strip()
        if sha:
            r = subprocess.run(["git", "-C", top, "stash", "store", "-m", label, sha], capture_output=True,
                               text=True, timeout=30)
            if r.returncode != 0:
                raise BackupError(f"git stash store failed: {r.stderr.strip()[:200]}")
            info["stash"] = label
        r = subprocess.run(["git", "-C", top, "ls-files", "--others", "--exclude-standard", "-z"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise BackupError(f"git ls-files failed: {r.stderr.strip()[:200]}")
        names = [n for n in r.stdout.split("\0") if n]
        if names:
            cap = _backup_cap_bytes()
            total = 0
            for n in names:
                try:
                    total += os.lstat(os.path.join(top, n)).st_size
                except OSError as e:
                    raise BackupError(f"cannot stat untracked file {n!r}: {e}")
            if total > cap:
                raise BackupError(f"untracked files total {total // (1024 * 1024)} MB, over the "
                                  f"{cap // (1024 * 1024)} MB backup cap: back up manually or commit first")
            d = _backup_dir()
            # The label is unique per call (epoch-pid-uuid); the tmp file is created
            # O_EXCL and hard-linked into place, so no backup is ever overwritten.
            final = d / f"{label}-untracked.tar.gz"
            tmp = d / f".{label}-untracked.tar.gz.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz", compresslevel=1) as tf:
                    for n in names:
                        try:
                            tf.add(os.path.join(top, n), arcname=n, recursive=False)
                        except OSError as e:   # unreadable or vanished: it would be lost, so block
                            raise BackupError(f"cannot back up untracked file {n!r}: {e}")
                if os.path.exists(final):
                    raise BackupError(f"backup name collision at {final}")
                os.link(tmp, final)
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
            info["untracked_tar"] = str(final)
        return info
    except BackupError:
        raise
    except Exception as e:
        raise BackupError(f"{type(e).__name__}: {e}")


def stash_remote(host, path, label):
    try:
        remote_cmd = f"cd {shlex.quote(path)} && git stash push -u -m {shlex.quote(label)}"
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host, remote_cmd],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


# --------------------------------------------------------------------------- destructive commands

# System directories dangerous to recursively delete at ANY depth.
_DANGEROUS_RM_ROOTS = ("/etc", "/root", "/var", "/usr", "/boot",
                       "/bin", "/sbin", "/lib", "/lib64", "/opt", "/srv")


def _expand_home_token(tok, home=None):
    """Expand `~`, `~/...`, `$HOME`, `${HOME}` (and their `/...` forms) so
    `rm -rf ~` and `rm -rf "${HOME}"` are recognised as the same target as the
    absolute home path."""
    home = home or _home()
    if tok in ("~", "~/"):
        return home
    if tok.startswith("~/"):
        return home + tok[1:]
    if tok in ("$HOME", "${HOME}"):
        return home
    if tok.startswith("$HOME/"):
        return home + tok[len("$HOME"):]
    if tok.startswith("${HOME}/"):
        return home + tok[len("${HOME}"):]
    return tok


def protected_roots():
    """{path: label} for directories that are catastrophic to delete AS
    THEMSELVES but whose subpaths are ordinary: /home, /Users, the user's home,
    every configured protected repo path, and every protected_paths entry.
    Relative and Windows-style paths are skipped."""
    cfg = get_config()
    roots = {"/home": "/home", "/Users": "/Users", _home(): "home directory"}
    for repo in cfg.get("protected_repos", []):
        name = repo.get("name") or "protected repo"
        for p in repo.get("paths", []):
            e = _expand(p)
            if e and e.startswith("/"):
                roots[e.rstrip("/") or "/"] = f"protected repo '{name}'"
    for p in cfg.get("protected_paths", []):
        e = _expand(p)
        if e and e.startswith("/"):
            roots[e.rstrip("/") or "/"] = e
    return roots


def irreplaceable_paths():
    return tuple(_expand(p) for p in get_config().get("irreplaceable_paths", []) if p)


def _abs_target(tgt):
    if tgt.startswith("/"):
        return os.path.normpath(tgt)
    try:
        return os.path.normpath(os.path.join(os.getcwd(), tgt))
    except OSError:
        return tgt


def _index_of_command(tokens, name):
    """Index of the first token that invokes `name`, matched on its basename so
    `/bin/rm` and `/usr/bin/find` count, or None."""
    for i, tok in enumerate(tokens):
        if tok.rsplit("/", 1)[-1] == name:
            return i
    return None


# Last path components that expand to (nearly) every entry of their directory.
_CONTENTS_GLOBS = frozenset({"*", ".*", "{*,.*}", "{.*,*}", ".[!.]*", ".[^.]*", ".??*"})


def _glob_contents_parent(tgt):
    """For `dir/*`, `dir/.*` (and the usual dotfile globs) return `dir`, the
    directory whose contents the glob deletes; `/*` gives "/". Otherwise None."""
    head, sep, last = tgt.rstrip("/").rpartition("/")
    if last not in _CONTENTS_GLOBS:
        return None
    if not sep:
        return "."   # bare `*`: the contents of the current directory
    return head or "/"


def is_dangerous_rm(cmd):
    """(blocked, reason) for a recursive rm of `/`, a system directory, a
    protected root, or an irreplaceable path or one of its ancestors,
    independent of flag order or separation (`-rf`, `-fr`, `-r -f`,
    `--recursive`). Ordinary subpaths (`rm -rf ./build`, `/tmp/x`) pass."""
    if not re.search(r"\brm\b", cmd):
        return False, None
    roots = protected_roots()
    precious = irreplaceable_paths()
    for seg in re.split(r"(?:&&|\|\||;|\||\n)", cmd):
        if not re.search(r"\brm\b", seg):
            continue
        try:
            tokens = shlex.split(seg)
        except ValueError:
            continue
        idx = _index_of_command(tokens, "rm")   # `rm`, `/bin/rm`, `/usr/bin/rm`
        if idx is None:
            continue
        tokens = tokens[idx + 1:]
        recursive = False
        targets = []
        for t in tokens:
            if t == "--":
                continue
            if t.startswith("--"):
                if t == "--recursive":
                    recursive = True
            elif t.startswith("-") and len(t) > 1:
                if "r" in t[1:] or "R" in t[1:]:
                    recursive = True
            else:
                targets.append(_expand_home_token(t))
        if not recursive:
            continue
        for shown in targets:
            # `dir/*`, `dir/.*` and friends delete the CONTENTS of `dir`, which is as
            # bad as deleting `dir` itself when `dir` is `/`, home or a protected root.
            parent = _glob_contents_parent(shown)
            tgt = shown if parent is None else parent
            norm = tgt.rstrip("/") or "/"
            if norm == "/":
                return True, "rm -r on root filesystem"
            if norm in roots:
                return True, f"rm -r on {roots[norm]} ({shown})"
            absn = _abs_target(norm)
            for d in precious:
                if absn == d or d.startswith(absn.rstrip("/") + "/"):
                    return True, f"rm -r would delete irreplaceable path ({d})"
            if any(norm == root or norm.startswith(root + "/") for root in _DANGEROUS_RM_ROOTS):
                return True, f"rm -r on system directory ({shown})"
    return False, None


def is_dangerous_find(cmd):
    """(blocked, reason) for `find <root-ish path> ... -delete`, the other
    recursive-delete primitive."""
    if not re.search(r"\bfind\b", cmd) or not re.search(r"-delete\b", cmd):
        return False, None
    roots = protected_roots()
    for seg in re.split(r"(?:&&|\|\||;|\||\n)", cmd):
        if not re.search(r"\bfind\b", seg) or not re.search(r"-delete\b", seg):
            continue
        try:
            tokens = shlex.split(seg)
        except ValueError:
            continue
        idx = _index_of_command(tokens, "find")   # `find`, `/usr/bin/find`
        if idx is None:
            continue
        j = idx + 1
        paths = []
        while j < len(tokens) and not tokens[j].startswith("-") and tokens[j] not in ("(", ")", "!"):
            paths.append(tokens[j])
            j += 1
        for p in paths:
            norm = _expand_home_token(p).rstrip("/") or "/"
            if norm == "/" or norm in roots or \
                    any(norm == root or norm.startswith(root + "/") for root in _DANGEROUS_RM_ROOTS):
                return True, f"find -delete on dangerous path ({p})"
    return False, None


def _split_segments(cmd):
    return re.split(r"(?:&&|\|\||;|\||\n)", cmd)


def _command_head(seg):
    """Base name of the command actually invoked in `seg`, skipping variable
    assignments and wrappers (sudo, env, time, nice, nohup, doas), so "reboot"
    or "mkfs" only counts when it IS the command, not a grep pattern, a file
    name or a `man` argument."""
    try:
        tokens = shlex.split(seg)
    except ValueError:
        tokens = seg.split()
    i = 0
    while i < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[i]):
        i += 1
    while i < len(tokens) and tokens[i] in ("sudo", "command", "env", "time", "nice", "nohup", "doas"):
        i += 1
        while i < len(tokens) and tokens[i].startswith("-"):
            i += 1
    if i >= len(tokens):
        return None
    return tokens[i].rsplit("/", 1)[-1]


def is_dangerous_shutdown(cmd):
    """Block shutdown/reboot/halt/poweroff only in command position, so
    `cat /var/run/reboot-required` and `grep -n reboot foo.py` pass."""
    for seg in _split_segments(cmd):
        if _command_head(seg) in ("shutdown", "reboot", "halt", "poweroff"):
            return True, "system shutdown command"
    return False, None


def is_dangerous_mkfs(cmd):
    for seg in _split_segments(cmd):
        head = _command_head(seg)
        if head and head.startswith("mkfs"):
            return True, "filesystem format"
    return False, None


_SSHD_CONFIG = "/etc/ssh/sshd_config"
_SSHD_WRITE_RE = re.compile(
    r"(>>?\s*" + re.escape(_SSHD_CONFIG) + r")"
    r"|(\btee\b[^\n|;&]*" + re.escape(_SSHD_CONFIG) + r")"
    r"|(\bsed\b[^\n|;&]*-i\S*[^\n|;&]*" + re.escape(_SSHD_CONFIG) + r")"
    r"|(\b(?:rm|mv|cp|install|dd)\b[^\n|;&]*" + re.escape(_SSHD_CONFIG) + r")"
)


def is_dangerous_sshd_edit(cmd):
    """Block writes to sshd_config, not reads (`grep PasswordAuthentication
    /etc/ssh/sshd_config` is a routine audit)."""
    if _SSHD_CONFIG not in cmd:
        return False, None
    if _SSHD_WRITE_RE.search(cmd):
        return True, "sshd_config write/edit"
    return False, None


_SHELL_C_RE = re.compile(
    r"^\s*(?:/usr/bin/|/bin/)?(?:bash|sh|zsh|ksh|dash)\s+(?:-[A-Za-z]+\s+)*-c\s+(.+)$", re.S
)
_EVAL_RE = re.compile(r"^\s*eval\s+(.+)$", re.S)


def extract_wrapped_command(line):
    """Unwrap `bash -c '...'` / `sh -c "..."` / `eval ...` so the inner command
    is scanned too. For `sh -c` the first argument is the script (later ones are
    positional parameters); for `eval` all remaining words are rejoined."""
    m = _SHELL_C_RE.match(line)
    if m:
        try:
            toks = shlex.split(m.group(1))
        except ValueError:
            toks = None
        return toks[0] if toks else None
    m = _EVAL_RE.match(line)
    if m:
        try:
            toks = shlex.split(m.group(1))
        except ValueError:
            toks = None
        return " ".join(toks) if toks else None
    return None


def check_hard_block(cmd, context="", _depth=0):
    """(blocked, reason) for every hard-block rule, including inside up to
    three levels of `bash -c` / `eval` wrapping."""
    for pat, reason in HARD_BLOCK_PATTERNS:
        if pat.search(cmd):
            return True, reason
    for check_fn in (is_dangerous_rm, is_dangerous_find, is_dangerous_shutdown,
                     is_dangerous_mkfs, is_dangerous_sshd_edit, is_protected_push_to_main):
        blocked, reason = check_fn(cmd)
        if blocked:
            return True, reason
    if _depth < 3:
        inner = extract_wrapped_command(cmd)
        if inner and inner != cmd:
            blocked, reason = check_hard_block(inner, context, _depth=_depth + 1)
            if blocked:
                return True, reason
    return False, None


AUTO_STASH_PATTERNS = _auto_stash_patterns()


def needs_stash(cmd):
    """The matched auto-backup reason, or None."""
    for pat, reason in AUTO_STASH_PATTERNS:
        if pat.search(cmd):
            return reason
    return None


# --------------------------------------------------------------------------- quoted-data neutralisation

_SHELL_EXEC_WORDS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "eval", "source", ".", "xargs",
                               "python", "python3", "perl", "ruby", "node"})
_EXEC_VERSIONED_RE = re.compile(r"^(?:python|perl|ruby|node)[\d.]*$")


def _is_exec_word(word):
    """A word that can execute quoted text, matched on its basename and for
    versioned interpreters (`python3.12`)."""
    base = word.rsplit("/", 1)[-1]
    return base in _SHELL_EXEC_WORDS or bool(_EXEC_VERSIONED_RE.match(base))


def neutralize_quoted_data(cmd):
    """`cmd` with the text of quoted string arguments removed, for the
    auto-backup scan only. A destructive pattern that appears only inside quotes
    (echo/printf text, a -m message, a test fixture) is data, not an op.
    Fail-safe: anything that might execute keeps its text, so a real op still
    backs up:
      - unbalanced quotes or an unterminated heredoc: unchanged;
      - an unquoted shell/eval/xargs/interpreter word anywhere (`bash -c '...'`,
        `echo '...' | sh`, `python3 -c "..."`): unchanged;
      - `$(...)` or backticks anywhere: unchanged;
      - a quoted word without whitespace (`git reset "--hard"`) keeps its text.
    Heredoc bodies are dropped (a heredoc feeding a shell trips the rule above)."""
    if "$(" in cmd or "`" in cmd:
        return cmd
    out, i, n, words, cur, heredocs = [], 0, len(cmd), [], [], []

    def flush():
        if cur:
            words.append("".join(cur))
            cur.clear()

    while i < n:
        c = cmd[i]
        if c == "\\" and i + 1 < n:
            out.append(cmd[i:i + 2])
            cur.append(cmd[i + 1])
            i += 2
            continue
        if c in "'\"":
            j, body = i + 1, []
            while j < n and cmd[j] != c:
                if c == '"' and cmd[j] == "\\" and j + 1 < n:
                    body.append(cmd[j + 1])
                    j += 2
                    continue
                body.append(cmd[j])
                j += 1
            if j >= n:
                return cmd   # unbalanced: scan as-is
            text = "".join(body)
            if not re.search(r"\s", text):
                out.append(text)   # one plain word: `git reset "--hard"` IS `git reset --hard`
                cur.append(text)
            else:
                out.append(c + c)
                cur.append("Q")
            i = j + 1
            continue
        if c == "<" and cmd.startswith("<<", i) and not cmd.startswith("<<<", i):
            m = re.match(r"<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\1", cmd[i:])
            if m:
                heredocs.append((m.group(2), bool(m.group(1))))
        if c == "\n" and heredocs:
            out.append(c)
            i += 1
            for delim, quoted in heredocs:
                m = re.compile(r"^[ \t]*" + re.escape(delim) + r"[ \t]*$", re.M).search(cmd, i)
                if not m:
                    return cmd   # unterminated heredoc: scan as-is
                if not quoted and re.search(r"\$\(|`|\$\{", cmd[i:m.start()]):
                    return cmd   # unquoted delimiter: the body is expanded
                i = m.end()
            heredocs = []
            continue
        if c.isspace() or c in ";&|()<>":
            flush()
        else:
            cur.append(c)
        out.append(c)
        i += 1
    flush()
    if any(_is_exec_word(w) for w in words):
        return cmd
    return "".join(out)


def neutralize_commit_messages(cmd):
    """Strip the VALUE of -m/--message/-F args from a `git commit`, so a commit
    message that describes `rm -rf /` is not scanned as a command. Only the
    message token is removed: chained commands after `&&`/`;`/`|` survive
    tokenisation and are still scanned. Unparseable input is returned unchanged."""
    if not _COMMIT_RE.search(cmd):
        return cmd
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return cmd
    out, skip_next = [], False
    for t in tokens:
        if skip_next:
            skip_next = False
            continue
        if t in ("-m", "--message", "-F", "--file"):
            skip_next = True
            continue
        if t.startswith("--message=") or t.startswith("--file="):
            continue
        if re.fullmatch(r"-[aqvnsepi]+[mF]", t):   # a commit flag cluster: `-qm <msg>`, `-am <msg>`
            skip_next = True
            continue
        if len(t) > 2 and t[0] == "-" and t[1] in "mF":   # an attached `-m<msg>`
            continue
        out.append(t)
    return " ".join(out)


# --------------------------------------------------------------------------- main

def _block(msg, event, **details):
    log_event("safety_block", {"mode": event, **details})
    print(f"SAFETY GUARDRAIL: Blocked: {msg}", file=sys.stderr)
    sys.exit(2)


def _remote_mode_for(host):
    remote = get_config().get("remote", {})
    mode = remote.get("mode", "block")
    allowed = remote.get("allowed_hosts") or []
    if mode == "stash" and allowed and host not in allowed:
        return "block"
    return mode


def main():
    t_start = time.monotonic()
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        sys.exit(0)

    # Fail open on malformed payloads: a hook that errors blocks the tool call.
    if not isinstance(data, dict):
        sys.exit(0)
    tool_input = data.get("tool_input", data) or {}
    if not isinstance(tool_input, dict):
        sys.exit(0)
    command = tool_input.get("command", "")
    if not command or not isinstance(command, str):
        sys.exit(0)

    get_config()   # an invalid config file raises here -> fail closed
    hook_cwd = data.get("cwd") or ""
    short = command[:200]

    # Neutralise commit-message bodies BEFORE splitting into lines, so prose in a
    # multi-line message is never scanned as a command.
    scan_command = neutralize_commit_messages(command)
    lines = [ln for ln in scan_command.splitlines() if ln.strip()]
    if not lines:
        sys.exit(0)
    orig_lines = list(lines)   # side effects (backup, ssh status) are decided from these only

    # Every ssh occurrence yields at most two extra block-only candidates (the text
    # from that occurrence and its local suffix), found in one linear pass. Hard
    # caps on occurrences and total work fail closed before anything is generated.
    offsets = [[m.start() for m in _SSH_WORD_RE.finditer(ln)] for ln in lines]
    if sum(len(o) for o in offsets) > MAX_SSH_OCCURRENCES:
        _block(f"too many ssh invocations in one command; split it. Cmd: {short}",
               "too_many_ssh", cmd=command[:300])
    work = 2 * sum(len(ln) - off for ln, offs in zip(orig_lines, offsets) for off in offs)
    if work > MAX_EXTRA_SCAN_BYTES:
        _block(f"command too large to verify safely; split it. Cmd: {short}",
               "too_large_to_verify", cmd=command[:300])
    seen = set(lines)
    for ln, offs in zip(orig_lines, offsets):
        for off in offs:
            for cand in (ln[off:], ssh_local_suffix(ln[off:])):
                if cand and cand not in seen:
                    seen.add(cand)
                    lines.append(cand)

    # 1. Hard blocks: the full command, each line, and each ssh-wrapped inner command.
    for idx, line in enumerate([scan_command] + lines):
        if idx > len(orig_lines) and time.monotonic() - t_start > EXTRA_SCAN_DEADLINE_S:
            _block(f"command too large to verify safely; split it. Cmd: {short}",
                   "scan_deadline", cmd=command[:300])
        blocked, reason = check_hard_block(line)
        if blocked:
            _block(f"{reason}. Unrecoverable op. Cmd: {short}", "hard_block", reason=reason, cmd=command[:300])
        blocked, reason = is_commit_on_protected_branch(line, hook_cwd)
        if blocked:
            _block(reason, "commit_on_protected_branch", reason=reason, cmd=command[:300])
        blocked, reason = is_implicit_push_to_protected(line, hook_cwd)
        if blocked:
            _block(f"{reason} Cmd: {short}", "implicit_push_to_protected", reason=reason, cmd=command[:300])
        for host, inner in ssh_block_candidates(line):
            blocked, reason = check_hard_block(inner)
            if blocked:
                _block(f"{reason} (via ssh {host}). Unrecoverable op. Cmd: {short}",
                       "hard_block_ssh", host=host, reason=reason, cmd=command[:300])

    # 1b. ssh plus a destructive git op that is not provably one clean remote
    #     argument: block, never guess.
    for line in orig_lines:
        if ssh_mixed_with_destructive(line, needs_stash):
            _block("ssh and a local destructive git op in one command (or the remote command "
                   f"boundary is unclear): run them as separate commands. Cmd: {short}",
                   "ssh_mixed_destructive", cmd=command[:300])

    # 2. Local auto-backup. Decided from the command with quoted data removed: a
    #    destructive pattern that is only text inside a quote is not an op. The
    #    target repo is the hook's cwd (a bare `git reset --hard` in the working
    #    directory is the most common form of the accident this guard exists
    #    for), moved by any `cd <path>` earlier in the line and by `git -C <path>`.
    backed_up = set()
    for line in [ln for ln in neutralize_quoted_data(command).splitlines() if ln.strip()]:
        if line.lstrip().startswith(("ssh ", "ssh\t")) or not needs_stash(line):
            continue
        targets = git_targets(line, hook_cwd, needs_stash)
        if not targets:   # the pattern spans segments: fall back to the whole line
            fallback = extract_target_path(line) or (hook_cwd or None)
            targets = [(_join_dir(hook_cwd or None, fallback) if fallback else None, [], line, [])]
        for target, dir_opts, seg, _ in targets:
            stash_reason = needs_stash(seg) or needs_stash(line)
            if target is None:
                continue
            if target is UNKNOWN_DIR:
                _block(f"{stash_reason}, but the target repo cannot be determined (a quoted path with "
                       f"spaces, `cd -`, or a variable). cd into the repo as its own command first, "
                       f"then run it. Cmd: {short}", "unknown_target", reason=stash_reason, cmd=command[:300])
            if dir_opts:
                _block(f"{stash_reason} with {' '.join(dir_opts)}: the hook cannot back up a tree "
                       f"addressed by --git-dir/--work-tree. Use `git -C <repo>` instead. Cmd: {short}",
                       "git_dir_option", reason=stash_reason, cmd=command[:300])
            target_path = _resolve(target)
            if target_path in backed_up or not check_dirty_local(target_path):
                continue
            label = f"guardrail-{int(time.time())}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
            err = None
            info = {"stash": None, "untracked_tar": None}
            try:
                info = backup_local(target_path, label)
            except BackupError as e:
                err = str(e)
            log_event("safety_stash", {
                "mode": "auto_backup_local", "reason": stash_reason, "path": target_path, "label": label,
                "success": err is None, "stash": info["stash"], "untracked_tar": info["untracked_tar"],
                "error": err, "cmd": line[:300],
            })
            if err is not None:
                print(f"SAFETY GUARDRAIL: Blocked: could not back up dirty tree at {target_path} "
                      f"before {stash_reason}: {err}. Back it up manually (git stash, or copy the "
                      f"untracked files) or investigate.", file=sys.stderr)
                sys.exit(2)
            backed_up.add(target_path)
            print(f"[guardrail] before {stash_reason} at {target_path}: backed up tracked changes as "
                  f"stash '{info['stash'] or 'none (no tracked changes)'}' and untracked files to "
                  f"{info['untracked_tar'] or 'none (no untracked files)'}. Working tree left untouched.",
                  file=sys.stderr)

    # 3. Remote (ssh-wrapped) destructive git ops.
    for line in orig_lines:
        host, inner = legacy_ssh(line)
        if not (host and inner):
            continue
        stash_reason = needs_stash(inner)
        if not stash_reason:
            continue
        if _remote_mode_for(host) == "block":
            _block(f"{stash_reason} on ssh {host}: destructive remote git ops are blocked by "
                   f"configuration (remote.mode / remote.allowed_hosts). Cmd: {short}",
                   "remote_blocked", host=host, reason=stash_reason, cmd=command[:300])
        target = extract_target_path(inner)
        if not target:
            _block(f"{stash_reason} on ssh {host} but the target repo is unknown (no 'cd <path>' in the "
                   f"remote command). Wrap it as 'cd <repo> && ...' so the tree can be protected. Cmd: {short}",
                   "remote_no_cwd", host=host, reason=stash_reason, cmd=command[:300])
        dirty = check_dirty_remote(host, target)
        if dirty is None:
            _block(f"{stash_reason} on ssh {host} at {target}, but the remote state could not be verified "
                   f"(ssh BatchMode auth failed or timed out). Check your ssh config for this host or run "
                   f"it manually after verifying.",
                   "remote_unverifiable", host=host, path=target, reason=stash_reason, cmd=line[:300])
        if dirty:
            label = f"guardrail-{host}-{int(time.time())}"
            ok = stash_remote(host, target, label)
            log_event("safety_stash", {"mode": "auto_stash_remote", "host": host, "reason": stash_reason,
                                       "path": target, "label": label, "success": ok, "cmd": line[:300]})
            if not ok:
                print(f"SAFETY GUARDRAIL: Blocked: could not stash dirty tree at {host}:{target} before "
                      f"{stash_reason}. Stash it manually on {host} or investigate.", file=sys.stderr)
                sys.exit(2)
            print(f"[guardrail] stashed dirty tree at {host}:{target} as '{label}' before {stash_reason}",
                  file=sys.stderr)

    sys.exit(0)


def run():
    """Console-script entry point. A guardrail must fail CLOSED on an internal
    error (including an invalid config file)."""
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print(f"SAFETY GUARDRAIL: internal error ({type(e).__name__}: {e}); blocking to fail closed.",
              file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    run()
