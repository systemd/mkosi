# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import contextvars
import logging
import os
import sys
from collections.abc import Iterator
from typing import Any, Final, NoReturn, Optional

# This global should be initialized after parsing arguments
ARG_DEBUG = contextvars.ContextVar("debug", default=False)
ARG_DEBUG_SHELL = contextvars.ContextVar("debug-shell", default=False)
ARG_DEBUG_SANDBOX = contextvars.ContextVar("debug-sandbox", default=False)
LEVEL = 0


def terminal_is_dumb() -> bool:
    if not sys.stdout.isatty() and not sys.stderr.isatty():
        return True

    return os.getenv("TERM", "") == "dumb"


class Style:
    # fmt: off
    bold: Final[str]   = "\033[0;1;39m"     if not terminal_is_dumb() else ""
    blue: Final[str]   = "\033[0;1;34m"     if not terminal_is_dumb() else ""
    gray: Final[str]   = "\033[0;38;5;245m" if not terminal_is_dumb() else ""
    red: Final[str]    = "\033[31;1m"       if not terminal_is_dumb() else ""
    yellow: Final[str] = "\033[33;1m"       if not terminal_is_dumb() else ""
    reset: Final[str]  = "\033[0m"          if not terminal_is_dumb() else ""
    # fmt: on


def die(message: str, *, hint: Optional[str] = None) -> NoReturn:
    logging.error(f"{message}")
    if hint:
        logging.info(f"({hint})")
    sys.exit(1)


def log_step(text: str) -> None:
    prefix = " " * LEVEL

    if sys.exc_info()[0]:
        # We are falling through exception handling blocks.
        # De-emphasize this step here, so the user can tell more
        # easily which step generated the exception. The exception
        # or error will only be printed after we finish cleanup.
        logging.info(f"{prefix}({text})")
    else:
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
