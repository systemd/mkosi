# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import contextvars
import logging
import os
import sys
from collections.abc import Iterator
from typing import Any, NoReturn, Optional

# This global should be initialized after parsing arguments
ARG_DEBUG = contextvars.ContextVar("debug", default=False)
ARG_DEBUG_SHELL = contextvars.ContextVar("debug-shell", default=False)
LEVEL = 0


class Style:
    bold = "\033[0;1;39m" if sys.stderr.isatty() else ""
    gray = "\033[0;38;5;245m" if sys.stderr.isatty() else ""
    red = "\033[31;1m" if sys.stderr.isatty() else ""
    yellow = "\033[33;1m" if sys.stderr.isatty() else ""
    reset = "\033[0m" if sys.stderr.isatty() else ""


def die(message: str,
        *,
        hint: Optional[str] = None) -> NoReturn:
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


class TtyFormatter(logging.Formatter):
    def __init__(self, fmt: Optional[str] = None, *args: Any, **kwargs: Any) -> None:
        fmt = fmt or "%(message)s"

        self.formatters = {
            logging.DEBUG:    logging.Formatter(f"‣ {Style.gray}{fmt}{Style.reset}"),
            logging.INFO:     logging.Formatter(f"‣ {fmt}"),
            logging.WARNING:  logging.Formatter(f"‣ {Style.yellow}{fmt}{Style.reset}"),
            logging.ERROR:    logging.Formatter(f"‣ {Style.red}{fmt}{Style.reset}"),
            logging.CRITICAL: logging.Formatter(f"‣ {Style.red}{Style.bold}{fmt}{Style.reset}"),
        }

        super().__init__(fmt, *args, **kwargs)

    def format(self, record: logging.LogRecord) -> str:
        return self.formatters[record.levelno].format(record)


def log_setup() -> None:
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(TtyFormatter())

    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.getLevelName(os.getenv("SYSTEMD_LOG_LEVEL", "info").upper()))
