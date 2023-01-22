import contextlib
import sys
from typing import Any, Iterator, NoReturn, Optional

# This global should be initialized after parsing arguments
ARG_DEBUG: set[str] = set()


class MkosiException(Exception):
    """Leads to sys.exit"""


class MkosiNotSupportedException(MkosiException):
    """Leads to sys.exit when an invalid combination of parsed arguments happens"""


def die(message: str, exception: type[MkosiException] = MkosiException) -> NoReturn:
    MkosiPrinter.warn(f"Error: {message}")
    raise exception(message)


def warn(message: str) -> None:
    MkosiPrinter.warn(f"Warning: {message}")


class MkosiPrinter:
    out_file = sys.stderr
    isatty = out_file.isatty()

    bold = "\033[0;1;39m" if isatty else ""
    red = "\033[31;1m" if isatty else ""
    reset = "\033[0m" if isatty else ""

    prefix = "‣ "

    level = 0

    @classmethod
    def _print(cls, text: str) -> None:
        cls.out_file.write(text)

    @classmethod
    def color_error(cls, text: Any) -> str:
        return f"{cls.red}{text}{cls.reset}"

    @classmethod
    def print_step(cls, text: str) -> None:
        prefix = cls.prefix + " " * cls.level
        if sys.exc_info()[0]:
            # We are falling through exception handling blocks.
            # De-emphasize this step here, so the user can tell more
            # easily which step generated the exception. The exception
            # or error will only be printed after we finish cleanup.
            cls._print(f"{prefix}({text})\n")
        else:
            cls._print(f"{prefix}{cls.bold}{text}{cls.reset}\n")

    @classmethod
    def info(cls, text: str) -> None:
        cls._print(text + "\n")

    @classmethod
    def warn(cls, text: str) -> None:
        cls._print(f"{cls.prefix}{cls.color_error(text)}\n")

    @classmethod
    @contextlib.contextmanager
    def complete_step(cls, text: str, text2: Optional[str] = None) -> Iterator[list[Any]]:
        cls.print_step(text)

        cls.level += 1
        try:
            args: list[Any] = []
            yield args
        finally:
            cls.level -= 1
            assert cls.level >= 0

        if text2 is not None:
            cls.print_step(text2.format(*args))


complete_step = MkosiPrinter.complete_step
