# SPDX-License-Identifier: LGPL-2.1+

import shutil
from pathlib import Path
from typing import Optional


def unlink_try_hard(path: Optional[Path]) -> None:
    if path is None:
        return

    path = Path(path)
    try:
        path.unlink()
        return
    except FileNotFoundError:
        return
    except Exception:
        pass

    shutil.rmtree(path)
