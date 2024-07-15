# SPDX-License-Identifier: LGPL-2.1-or-later

import subprocess
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Protocol, TypeVar, Union

# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[str]
    Popen = subprocess.Popen[str]
else:
    CompletedProcess = subprocess.CompletedProcess
    Popen = subprocess.Popen

# Borrowed from https://github.com/python/typeshed/blob/3d14016085aed8bcf0cf67e9e5a70790ce1ad8ea/stdlib/3/subprocess.pyi#L24
_FILE = Union[None, int, IO[Any]]
PathString = Union[Path, str]

# Borrowed from
# https://github.com/python/typeshed/blob/ec52bf1adde1d3183d0595d2ba982589df48dff1/stdlib/_typeshed/__init__.pyi#L19
# and
# https://github.com/python/typeshed/blob/ec52bf1adde1d3183d0595d2ba982589df48dff1/stdlib/_typeshed/__init__.pyi#L224
_T_co = TypeVar("_T_co", covariant=True)

class SupportsRead(Protocol[_T_co]):
    def read(self, __length: int = ...) -> _T_co: ...
