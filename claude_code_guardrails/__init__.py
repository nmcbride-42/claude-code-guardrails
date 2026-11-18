"""A PreToolUse safety hook for Claude Code's Bash tool."""
from .guardrail import check_hard_block, load_config, main, needs_stash, run, set_config

__all__ = ["check_hard_block", "load_config", "main", "needs_stash", "run", "set_config"]
__version__ = "0.1.0"
