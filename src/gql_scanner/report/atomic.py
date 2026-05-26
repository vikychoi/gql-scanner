"""Atomic text writes so an interrupted or concurrent read never sees a torn file.

Used for every CSV write — the incremental mirrors during a scan and the final
canonical output: write to a temp file in the destination directory, then
``os.replace`` (atomic for same-directory targets on POSIX and Windows). ``newline=""``
preserves the ``\\n`` line endings the CSV layer emits without translation.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        # On success the temp was renamed away; on failure it lingers — remove it.
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
