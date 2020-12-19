# SPDX-License-Identifier: LGPL-2.1+

import sys


class MkosiPrinter:
    out_file = sys.stderr
    isatty = out_file.isatty()

    bold = "\033[0;1;39m" if isatty else ""
    red = "\033[31;1m" if isatty else ""
    reset = "\033[0m" if isatty else ""

    prefix = "‣ "

    @classmethod
    def _print(cls, text: str) -> None:
        cls.out_file.write(text)

    @classmethod
    def print_step(cls, text: str) -> None:
        cls._print(f"{cls.prefix}{cls.bold}{text}{cls.reset}\n")

    @classmethod
    def info(cls, text: str) -> None:
        cls._print(text + "\n")

    @classmethod
    def warn(cls, text: str) -> None:
        cls._print(f"{cls.prefix}{cls.red}{text}{cls.reset}\n")
