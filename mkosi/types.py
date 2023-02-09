import subprocess
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Sequence, Union

# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[Any]
    Popen = subprocess.Popen[Any]
else:
    CompletedProcess = subprocess.CompletedProcess
    Popen = subprocess.Popen

# Borrowed from https://github.com/python/typeshed/blob/3d14016085aed8bcf0cf67e9e5a70790ce1ad8ea/stdlib/3/subprocess.pyi#L24
_FILE = Union[None, int, IO[Any]]
PathString = Union[Path, str]

CommandArgument = Union[str, Path, int]
CommandLine = Sequence[CommandArgument]
MutableCommandLine = list[CommandArgument]
