import contextlib
import sys
from typing import Any, Iterator, NoReturn, Optional

# This global should be initialized after parsing arguments
ARG_DEBUG: set[str] = set()


class Style:
    Bold = "\033[0;1;39m" if sys.stderr.isatty() else ""
    Red = "\033[31;1m" if sys.stderr.isatty() else ""
    Yellow = "\033[33;1m" if sys.stderr.isatty() else ""
    Reset = "\033[0m" if sys.stderr.isatty() else ""


PREFIX = "‣ "
LEVEL = 0


def log_step(text: str) -> None:
    prefix = PREFIX + " " * LEVEL
    if sys.exc_info()[0]:
        # We are falling through exception handling blocks.
        # De-emphasize this step here, so the user can tell more
        # easily which step generated the exception. The exception
        # or error will only be printed after we finish cleanup.
        print(f"{prefix}({text})", file=sys.stderr)
    else:
        print(f"{prefix}{Style.Bold}{text}{Style.Reset}", file=sys.stderr)


def color_error(text: Any) -> str:
    return f"{Style.Red}{text}{Style.Reset}"


def color_warning(text: Any) -> str:
    return f"{Style.Yellow}{text}{Style.Reset}"


def log_info(text: str) -> None:
    print(f"{PREFIX}{text}", file=sys.stderr)


def log_warning(text: str) -> None:
    print(f"{PREFIX}{color_warning(text)}", file=sys.stderr)


def log_error(text: str) -> None:
    print(f"{PREFIX}{color_error(text)}", file=sys.stderr)


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


def die(
        message: str,
        exception: Optional[Exception] = None,
        *,
        hint: Optional[str] = None) -> NoReturn:
    log_error(f"Error: {message}")
    if hint:
        log_info(f"({hint})")
    raise exception or RuntimeError(message)

