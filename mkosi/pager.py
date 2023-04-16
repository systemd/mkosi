# SPDX-License-Identifier: LGPL-2.1+

import os
import pydoc
from typing import Optional


def page(text: str, enabled: Optional[bool]) -> None:
    if enabled:
        # Initialize less options from $MKOSI_LESS or provide a suitable fallback.
        # F: don't page if one screen
        # X: do not clear screen
        # M: verbose prompt
        # K: quit on ^C
        os.environ["LESS"] = os.getenv("MKOSI_LESS", "FXMK")
        pydoc.pager(text)
    else:
        print(text)
