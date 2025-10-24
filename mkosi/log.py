# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import contextvars
import logging
import os
import sys
from collections.abc import Iterator
from typing import Any, NoReturn, Optional

from mkosi.sandbox import Style, terminal_is_dumb

# This global should be initialized after parsing arguments
ARG_DEBUG = contextvars.ContextVar("debug", default=False)
ARG_DEBUG_SHELL = contextvars.ContextVar("debug-shell", default=False)
ARG_DEBUG_SANDBOX = contextvars.ContextVar("debug-sandbox", default=False)
LEVEL = 0


def die(message: str, *, hint: Optional[str] = None) -> NoReturn:
    logging.error(f"{message}")
    if hint:
        logging.info(f"({hint})")
    sys.exit(1)


class ConsoleCodes:
    OSC = "\033]"
    CSI = "\033["
    ST = "\033\\"
    # \033\\ is one possible ECMA-48 string terminators, BEL would be valid for most terminal emulators as
    # well, but kitty, annoyingly, actually rings the bell in that case. Other string terminators would be
    # valid as well, but this one worked for:
    # - alacritty
    # - ghostty
    # - gnome-terminal
    # - kitty
    # - konsole
    # - ptyxis
    # - xterm
    # References:
    # https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#window-title
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Operating_System_Command_sequences
    # https://ghostty.org/docs/vt/concepts/sequences#osc-sequences
    # https://sw.kovidgoyal.net/kitty/shell-integration/#notes-for-shell-developers

    @classmethod
    def set_window_title(cls, title: str) -> str:
        return f"{cls.OSC}0;mkosi: {title}{cls.ST}"

    @classmethod
    def push_window_title(cls) -> str:
        """Push the window title on the window title stack."""
        # not supported by konsole
        return f"{cls.CSI}22t"

    @classmethod
    def pop_window_title(cls) -> str:
        """Pop latest window title from the window title stack."""
        # not supported by konsole
        return f"{cls.CSI}23t"


def log_step(text: str) -> None:
    prefix = " " * LEVEL

    if sys.exc_info()[0]:
        # We are falling through exception handling blocks.
        # De-emphasize this step here, so the user can tell more
        # easily which step generated the exception. The exception
        # or error will only be printed after we finish cleanup.
        if not terminal_is_dumb():
            print(ConsoleCodes.set_window_title(text), file=sys.stderr, end="")
        logging.info(f"{prefix}({text})")
    else:
        if not terminal_is_dumb():
            print(ConsoleCodes.set_window_title(text), file=sys.stderr, end="")
        logging.info(f"{prefix}{Style.bold}{text}{Style.reset}")


def log_notice(text: str) -> None:
    logging.info(f"{Style.bold}{text}{Style.reset}")


@contextlib.contextmanager
def complete_step(text: str, text2: Optional[str] = None) -> Iterator[list[Any]]:
    global LEVEL

    log_step(text)

    LEVEL += 1
    try:
        args: list[Any] = []
        yield args
    finally:
        LEVEL -= 1
        assert LEVEL >= 0

    if text2 is not None:
        log_step(text2.format(*args))


class Formatter(logging.Formatter):
    def __init__(self, fmt: Optional[str] = None, *args: Any, **kwargs: Any) -> None:
        fmt = fmt or "%(message)s"

        self.formatters = {
            logging.DEBUG:    logging.Formatter(f"‣ {Style.gray}{fmt}{Style.reset}"),
            logging.INFO:     logging.Formatter(f"‣ {fmt}"),
            logging.WARNING:  logging.Formatter(f"‣ {Style.yellow}{fmt}{Style.reset}"),
            logging.ERROR:    logging.Formatter(f"‣ {Style.red}{fmt}{Style.reset}"),
            logging.CRITICAL: logging.Formatter(f"‣ {Style.red}{Style.bold}{fmt}{Style.reset}"),
        }  # fmt: skip

        super().__init__(fmt, *args, **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        return self.formatters[record.levelno].format(record)


def log_setup(default_log_level: str = "info") -> None:
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(Formatter())

    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(
        logging.getLevelName(os.getenv("SYSTEMD_LOG_LEVEL", default_log_level).upper())
    )


@contextlib.contextmanager
def stash_terminal_title() -> Iterator[None]:
    try:
        if not terminal_is_dumb():
            print(ConsoleCodes.push_window_title(), file=sys.stderr, end="")

        yield
    finally:
        if not terminal_is_dumb():
            print(ConsoleCodes.pop_window_title(), file=sys.stderr, end="")
