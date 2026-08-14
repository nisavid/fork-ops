"""Bounded stable reads for security-sensitive local authority files."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Final, Literal

READ_CHUNK_BYTES: Final = 65_536
StableFileFailure = Literal["not_regular", "too_large", "changed"]


class StableFileReadError(OSError):
    """A local authority file failed a stable regular-file invariant."""

    def __init__(self, failure: StableFileFailure) -> None:
        super().__init__(failure)
        self.failure: Final = failure


def _read_bytes(descriptor: int, count: int) -> bytes:
    return os.read(descriptor, count)


def read_stable_regular_file(
    path: str | Path,
    *,
    maximum_bytes: int,
    directory_descriptor: int | None = None,
) -> bytes:
    """Read one no-follow regular file fully under a byte and stability bound."""
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        dir_fd=directory_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StableFileReadError("not_regular")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = _read_bytes(
                descriptor,
                min(READ_CHUNK_BYTES, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise StableFileReadError("too_large")
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or after.st_size != len(payload):
            raise StableFileReadError("changed")
        return payload
    finally:
        os.close(descriptor)
