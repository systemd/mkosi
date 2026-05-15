import os
import sys


def terminal_is_dumb() -> bool:
    return not sys.stdout.isatty() or not sys.stderr.isatty() or os.getenv("TERM", "") == "dumb"


# fmt: off
ANSI_BOLD      = "\033[0;1;39m"     if not terminal_is_dumb() else ""
ANSI_BLUE      = "\033[0;1;34m"     if not terminal_is_dumb() else ""
ANSI_GRAY      = "\033[0;38;5;245m" if not terminal_is_dumb() else ""
ANSI_RED       = "\033[31;1m"       if not terminal_is_dumb() else ""
ANSI_YELLOW    = "\033[33;1m"       if not terminal_is_dumb() else ""
ANSI_RESET     = "\033[0m"          if not terminal_is_dumb() else ""
# fmt: on
