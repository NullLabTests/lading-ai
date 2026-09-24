from __future__ import annotations

import hashlib
import os
from typing import BinaryIO


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def sha256_stream(stream: BinaryIO, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(chunk), b""):
        h.update(block)
    return h.hexdigest()


def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0