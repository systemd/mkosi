# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import pydoc


def page(text: str, enabled: bool | None) -> None:
    if enabled:
        # Initialize less options from $MKOSI_LESS or provide a suitable fallback.
        # F: don't page if one screen
        # X: do not clear screen
        # M: verbose prompt
        # K: quit on ^C
        # R: allow rich formatting
        os.environ["LESS"] = os.getenv("MKOSI_LESS", "FXMKR")
        pydoc.pager(text)
    else:
        print(text)
