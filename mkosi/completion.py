# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import dataclasses
import io
import shlex
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Optional, Union

from mkosi.config import SETTINGS, SETTINGS_LOOKUP_BY_DEST, Args, CompGen, Verb, create_argument_parser
from mkosi.log import die


@dataclasses.dataclass(frozen=True)
class CompletionItem:
    short: Optional[str]
    long: Optional[str]
    help: Optional[str]
    nargs: Union[str, int]
    choices: list[str]
    compgen: CompGen


def collect_completion_arguments() -> list[CompletionItem]:
    parser = create_argument_parser()

    options = [
        CompletionItem(
            short=next((s for s in action.option_strings if not s.startswith("--")), None),
            long=next((s for s in action.option_strings if s.startswith("--")), None),
            help=action.help,
            nargs=action.nargs or 0,
            choices=[str(c) for c in action.choices] if action.choices is not None else [],
            compgen=CompGen.from_action(action),
        )
        for action in parser._actions
        if (action.option_strings and
            action.help != argparse.SUPPRESS and
            action.dest not in SETTINGS_LOOKUP_BY_DEST)
    ]

    options += [
        CompletionItem(
            short=setting.short,
            long=setting.long,
            help=setting.help,
            nargs=setting.nargs or 1,
            choices=[str(c) for c in setting.choices] if setting.choices is not None else [],
            compgen=setting.compgen,
        )
        for setting in SETTINGS
    ]

    return options


def finalize_completion_bash(options: list[CompletionItem], resources: Path) -> str:
    def to_bash_array(name: str, entries: Iterable[str]) -> str:
        return f"declare -a {name.replace('-', '_')}=(" + " ".join(shlex.quote(str(e)) for e in entries) + ")"

    def to_bash_hasharray(name: str, entries: Mapping[str, Union[str, int]]) -> str:
        return (
            f"declare -A {name.replace('-', '_')}=(" +
            " ".join(f"[{shlex.quote(str(k))}]={shlex.quote(str(v))}" for k, v in entries.items()) + ")"
        )

    completion = resources / "completion.bash"

    options_by_key = {o.short: o for o in options if o.short} | {o.long: o for o in options if o.long}

    with io.StringIO() as c:
        c.write("# SPDX-License-Identifier: LGPL-2.1-or-later\n\n")
        c.write(to_bash_array("_mkosi_options", options_by_key.keys()))
        c.write("\n\n")

        nargs = to_bash_hasharray("_mkosi_nargs", {optname: v.nargs for optname, v in options_by_key.items()})
        c.write(nargs)
        c.write("\n\n")

        choices = to_bash_hasharray(
            "_mkosi_choices", {optname: " ".join(v.choices) for optname, v in options_by_key.items() if v.choices}
        )
        c.write(choices)
        c.write("\n\n")

        compgen = to_bash_hasharray(
            "_mkosi_compgen",
            {optname: v.compgen.to_bash() for optname, v in options_by_key.items() if v.compgen != CompGen.default},
        )
        c.write(compgen)
        c.write("\n\n")

        c.write(to_bash_array("_mkosi_verbs", [str(v) for v in Verb]))
        c.write("\n\n\n")

        c.write(completion.read_text())

        return c.getvalue()


def finalize_completion_fish(options: list[CompletionItem], resources: Path) -> str:
    with io.StringIO() as c:
        c.write("# SPDX-License-Identifier: LGPL-2.1-or-later\n\n")
        c.write("complete -c mkosi -f\n")

        c.write("complete -c mkosi -n '__fish_is_first_token' -a \"")
        c.write(" ".join(str(v) for v in Verb))
        c.write("\"\n")

        for option in options:
            if not option.short and not option.long:
                continue

            c.write("complete -c mkosi ")
            if option.short:
                c.write(f"-s {option.short.lstrip('-')} ")
            if option.long:
                c.write(f"-l {option.long.lstrip('-')} ")
            if isinstance(option.nargs, int) and option.nargs > 0:
                c.write("-r ")
            if option.choices:
                c.write("-a \"")
                c.write(" ".join(option.choices))
                c.write("\" ")
            if option.help is not None:
                help = option.help.replace("'", "\\'")
                c.write(f"-d \"{help}\" ")
            c.write(option.compgen.to_fish())
            c.write("\n")
        return c.getvalue()


def finalize_completion_zsh(options: list[CompletionItem], resources: Path) -> str:
    def to_zsh_array(name: str, entries: Iterable[str]) -> str:
        return f"declare -a {name.replace('-', '_')}=(" + " ".join(shlex.quote(str(e)) for e in entries) + ")"

    completion = resources / "completion.zsh"

    with io.StringIO() as c:
        c.write("#compdef mkosi\n")
        c.write("# SPDX-License-Identifier: LGPL-2.1-or-later\n\n")

        c.write(to_zsh_array("_mkosi_verbs", [str(v) for v in Verb]))
        c.write("\n\n")


        c.write(completion.read_text())
        c.write("\n")

        c.write("_arguments -s \\\n")
        c.write("    '(- *)'{-h,--help}'[Show this help]' \\\n")
        c.write("    '(- *)--version[Show package version]' \\\n")

        for option in options:
            if not option.short and not option.long:
                continue

            posix = option.help and "'" in option.help
            open_quote = "$'" if posix else "'"
            if option.short and option.long:
                c.write(f"    '({option.short} {option.long})'{{{option.short},{option.long}}}{open_quote}")
            else:
                c.write(f"    {open_quote}{option.short or option.long}")

            if option.help:
                help = option.help.replace("'", r"\'")
                c.write(f"[{help}]")
            if option.choices:
                # TODO: maybe use metavar here? At least for me it's not shown, though
                c.write(":arg:(")
                c.write(" ".join(option.choices))
                c.write(")")
            c.write(option.compgen.to_zsh())
            c.write("' \\\n")

        c.write("    '*::mkosi verb:_mkosi_verb'\n\n")

        return c.getvalue()


def print_completion(args: Args, *, resources: Path) -> None:
    if not args.cmdline:
        die(
            "No shell to generate completion script for specified",
            hint="Please specify either one of: bash, fish, zsh"
        )

    shell = args.cmdline[0]
    completion_args = collect_completion_arguments()
    if shell == "bash":
        print(finalize_completion_bash(completion_args, resources))
    elif shell == "fish":
        print(finalize_completion_fish(completion_args, resources))
    elif shell == "zsh":
        print(finalize_completion_zsh(completion_args, resources))
    else:
        die(
            f"{shell!r} is not supported for completion scripts.",
            hint="Please specify either one of: bash, fish, zsh"
        )
